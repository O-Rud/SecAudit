param ([string]$ConfigFile)
cls

#region Functions

Function Invoke-SQLQuery{
<#
.SYNOPSIS
    Runs query against MSSQLServer database
.PARAMETER text
    SQL command text.
.PARAMETER base
    SQL Database Name
.PARAMETER server
    SQL Server instance name
.PARAMETER CommandType
	Optional parameter. SQL Command type. Must be one of: 'StoredProcedure', 'TableDirect' or 'Text'. Default value is 'Text'.
.PARAMETER CommandTimeout
	Optional parameter. Timeout in seconds for sql query execution. Default value 30.
.PARAMETER CommandTimeout
	Optional parameter. Timeout in seconds for sql server connection.
.PARAMETER params
	Optional paremeter. Hashtable with named attributes, wich will be sent to parameterised query.
.PARAMETER ReturnDataset
	Optional switch parameter. If specified results will be returned in dataset. Otherwise Function returns array of rows.
.OUTPUTS
    Query result. Output type depends on ReturnDataset parameter.
#>
Param 
	(
	[parameter(Mandatory=$true)][String]$text   =     $(throw 'Ошибка! В переменной $text должен находиться текст запроса.'),
    [parameter(Mandatory=$true)][String]$base   =     $(throw 'Ошибка! В переменной $base должно находиться имя базы данных.'),
	[parameter(Mandatory=$true)][String]$server =     $(throw 'Ошибка! В переменной $server должно находиться имя сервера баз данных.'),
	[parameter()][validateset('StoredProcedure','TableDirect','Text')][String]$CommandType= 'Text',
    [String]$CommandTimeout=30,
	[String]$ConnTimeout=15,
	[hashtable]$params,
	[switch]$ReturnDataset
	)
$ConnectionString = "Data Source=$server;Initial Catalog=$base;Integrated Security=SSPI;Connect Timeout=$ConnTimeout"
$Connection = new-Object Data.SqlClient.SqlConnection ($ConnectionString)
$Command = new-Object Data.SqlClient.SqlCommand ($text,$Connection)
Register-ObjectEvent -inputObject $Connection -eventName InfoMessage -Action {$event.SourceEventArgs.message  | Write-host -ForegroundColor DarkGreen} | Out-Null
if ($params.count -gt 0)
	{
	foreach ($key  in $params.keys)
		{
		if ($params[$key] -ne $null) {
			$Command.Parameters.AddWithValue($key, $params[$key]) | Write-Debug
			}
		Else
			{
			$Command.Parameters.AddWithValue($key, [dbnull]::Value) | Write-Debug
			}
		}
	}
$Command.CommandType = $commandtype
$Command.CommandTimeout = $CommandTimeout
$DataSet                   =   new-Object Data.DataSet
$DataAdapter                 =   new-Object Data.SqlClient.SqlDataAdapter ($Command)
$DataAdapter.Fill($DataSet) | Write-Debug
if ($Connection.State -ne 'Closed')
	{
	$Connection.Close()
	}
if ($ReturnDataset) {return $DataSet}
Else {$dataset.tables | %{$_.rows}}
trap
	{
	if ($Connection.State -ne 'Closed')
		{
		$Connection.Close()
		}
	Write-Error "Ошибка выполнения запроса к серверу: $server :$_"
	}
} 

Function Add-ColumnToTable{#Filter Creates column with name and type providen in params and adds it to inputobject datatable
	param(
		[data.datatable]$table,
		[string]$Name,
		[string]$Type
		)
    $Column = new-object Data.DataColumn; #creating column object
    $Column.DataType = [System.Type]::GetType($Type); #assign column type
    $Column.ColumnName = $name; #assign column name
    $Table.Columns.Add($Column); #add column to table
    }

Function Add-ItemValue{
param(
[string]$tblname,
[string]$KeyName,
[string]$ValName,
[string]$Value
)
$SQLQuery = "insert $tblname ($ValName) output inserted.* values(@$ValName)"
[array]$res = Invoke-SQLQuery -server $SQLServer -base $Database -text $SQLQuery -params @{"$ValName"=$Value}
if ($res.Count -gt 0)
	{
	$res[0].$KeyName
	}
else
	{
	throw "Failed to add $Valname = $value to $tblname"
	}
}

Filter Out-LogFile{
Param
	(
	[string]$FilePath,
	[switch]$Append
	)
Write-Host "$((Get-Date).tostring()): $_"
"$((Get-Date).tostring()): $_" | Out-File -FilePath $FilePath -Append:$Append
} 

#endregion Functions

$CompInfo = gwmi win32_computersystem
$ComputerName = "$($Compinfo.name).$($compInfo.Domain)"
$encoding = [text.encoding]::unicode
#region LoadConfig
#Load from XML File
if ($ConfigFile -eq ""){
	$InvocationFolder = Split-path -Path $MyInvocation.mycommand.path -Parent
	$ConfigFile = Join-Path $InvocationFolder 'SecAuditConf.xml'
	}
if (-not (Test-Path $ConfigFile)) {throw "Config file $ConfigFile is inaccessable"}
$xml = [xml]$(gc $ConfigFile)
[string]$SQLServer = $xml.config.server
[string]$Database = $xml.config.DB
[string]$LogFolder = $xml.config.LogFolder
[string]$LogName = 'Security'

#Write Log Beginning
if (-not (test-path $LogFolder)) {md $LogFolder}
$LogFile = Join-path $LogFolder "$($ComputerName)_AuditExport.log"
"`r`n`r`n====================    First Line    ====================" | Out-LogFile $Logfile -Append
"Starting EventLog Export" | Out-LogFile $Logfile -Append
"Test DB Connection (Server:$SQLServer DB:$Database)... " | Out-LogFile $Logfile -Append -NoNewline

#Load from SQL DB
try{
	$SQLQuery = "Select PropName, PropValue from Conf where PropType = 'EventCollector' OR PropType = 'Common'"
	$ConfRes = Invoke-SQLQuery -server $SQLServer -base $Database -text $SQLQuery
	$SQLQuery = "Select EventID from KnownEventIDs"
	$KnownEventIds = Invoke-SQLQuery -server $SQLServer -base $Database -text $SQLQuery | Select -ExpandProperty EventID
	"Success" | Out-LogFile $Logfile -Append
	}
catch
	{
	"Failed!" | Out-LogFile $Logfile -Append
	$_ | Out-LogFile $Logfile -Append
	"Cannot establish DB connection. Finishing script" | Out-LogFile $Logfile -Append
	throw "DB Connection failed"
	return
	}
$sqlconf = @{}
$ConfRes | %{$sqlconf[$_.PropName]+=@($_.PropValue)}
[int]$Blocksize = [int]$($sqlconf.BlockSize)
[int]$SqlTimeout = [int]$($sqlconf.SQLTimeout)
[string]$SMTPServer = $sqlconf.SmtpServer
[string]$MailFrom = $sqlconf.MailFrom
[array]$MailTo = $sqlconf.MailTo
#endregion LoadConfig

#region Load data from SQL
$SQLQuery = "Select * from Computers"
$Computers = @{}
Invoke-SQLQuery -server $SQLServer -base $Database -text $SQLQuery | %{$Computers[$_.ComputerName]=$_.ComputerID}
if ($Computers.keys -contains $ComputerName)
	{
	$ComputerID = $Computers[$ComputerName]
	}
else
	{
	$ComputerID = Add-ItemValue -tblname Computers -KeyName ComputerID -ValName ComputerName -Value $ComputerName
	$Computers[$ComputerName]=$ComputerID
	}
#endregion Load data from SQL

$SQLQuery = "Select * from EntryTypes"
$EntryTypes = @{}
Invoke-SQLQuery -server $SQLServer -base $Database -text $SQLQuery | %{$EntryTypes[$_.EntryTypeName]=$_.EntryTypeID}
$SQLQuery = "Select * from Sources"
$Sources = @{}
Invoke-SQLQuery -server $SQLServer -base $Database -text $SQLQuery | %{$Sources[$_.SourceName]=$_.SourceID}

#region Define_DataTables
#Creating DataTable EventHeaders
$tblEventHeaders = new-object Data.DataTable
Add-ColumnToTable -table $tblEventHeaders -Name "Id" -Type "System.Int64"              #Add Column Id
Add-ColumnToTable -table $tblEventHeaders -Name "EventRecordId" -Type "System.Int64"   #Add Column EventRecordId
Add-ColumnToTable -table $tblEventHeaders -Name "TimeGenerated" -Type "System.DateTime"     #Add Column DateTime
Add-ColumnToTable -table $tblEventHeaders -Name "SourceID" -Type "System.Int32"         #Add Column Source
Add-ColumnToTable -table $tblEventHeaders -Name "EntryTypeID" -Type "System.Int32"         #Add Column OpCode
Add-ColumnToTable -table $tblEventHeaders -Name "UserName" -Type "System.String"         #Add Column [User]
Add-ColumnToTable -table $tblEventHeaders -Name "ComputerID" -Type "System.Int32"       #Add Column ComputerID
Add-ColumnToTable -table $tblEventHeaders -Name "Eventid" -Type "System.Int32"         #Add Column Eventid
Add-ColumnToTable -table $tblEventHeaders -Name "Message" -Type "System.String"        #Add Column Message
Add-ColumnToTable -table $tblEventHeaders -Name "CategoryNumber" -Type "System.Int32"   #Add Column TaskCategory


#Create Datatable Properties
$tblProperties = new-object Data.DataTable
Add-ColumnToTable -table $tblProperties -Name "Id" -Type "System.Int64"              #Add Column Id
Add-ColumnToTable -table $tblProperties -Name "EventHeaderId" -Type "System.Int64"   #Add Column Id
Add-ColumnToTable -table $tblProperties -Name "PropertyNumber" -Type "System.Int32"     #Add Column Id
Add-ColumnToTable -table $tblProperties -Name "Value" -Type "System.String"     #Add Column Id
#endregion Define_DataTables

"Getting events from $Logname Log..." | Out-LogFile $Logfile -Append
try{
	#Get last eventrecordid for current server in Database
    #$Sqlquery = "Select isnull(Max(EventRecordid),0) as lastevent from EventHeaders where Computer like @computername and Logname = @logname"
	$sqlquery = "Select @computerid ComputerID, isnull(Max(EventRecordid),0) as lastevent from EventHeaders where ComputerID = @ComputerID"
	$params = @{ComputerID = $ComputerID}
	[array]$Res = Invoke-SQLQuery -text $sqlquery -server $SqlServer -base $Database -params $params
    if ($res.count -eq 0) {$(throw "SartPosition retrieval faild. Probably SQLServer problem.")}
    $StartPosition = $res[0].lastevent
	If ($StartPosition -eq 0) {
		$Events = Get-EventLog -LogName $LogName -AsBaseObject
		$EndPosition = $Events[0].Index
		[array]::Reverse($Events)
		$StartPosition = $Events[0].Index
		}
	else{
		$SQLQuery = 'Select TimeGenerated from EventHeaders where ComputerID=@ComputerID and Eventrecordid = @Eventrecordid'
		$params = @{ComputerID = $ComputerID;Eventrecordid=$StartPosition}
		$LastRecord = Invoke-SQLQuery -text $SQLQuery -server $SqlServer -base $Database -params $params
		$LastEventTime = $LastRecord.timegenerated
		$Events = Get-EventLog -LogName $LogName -AsBaseObject -After $LastEventTime.AddSeconds(-5)
		$EndPosition = $Events[0].Index
		[array]::Reverse($Events)
		}
    
    if ($StartPosition -gt $EndPosition)
        {
        $Message = "$((Get-Date).tostring()): Error! Latest EventRecordId in $EventLogName of Server $Computername less then last recorded in Database."
        $message | Out-LogFile $logfile -Append
        Send-MailMessage -To $MailTo -Subject "Event Log Export Error Report" -From $MailFrom -SmtpServer $Smtpsrv -Body $message -BodyAsHtml -Encoding $encoding
        }
    "Start position: $StartPosition" | Out-LogFile $Logfile -Append
    "End position: $EndPosition" | Out-LogFile $Logfile -Append
    "Records to write: $($EndPosition - $StartPosition)" | Out-LogFile $Logfile -Append
    "Blocks to write: $(($EndPosition - $StartPosition)/$Blocksize)" | Out-LogFile $Logfile -Append
    #define Connection object:
    $ConnectionString = "Data Source=$SqlServer;Initial Catalog=$DataBase;Integrated Security=SSPI;Connection Timeout=$SQLTimeout"
    $Connection = new-Object Data.SqlClient.SqlConnection ($ConnectionString)
    $Connection.open()
    $BulkCopyOptions = New-Object data.sqlclient.SqlBulkCopyOptions
    #Get start Id in EventHeaders for bulk Insert
    "Reserving block for bulk insert" | Out-LogFile $Logfile -Append
	$SqlQuery = "declare @id bigint; exec pr_GetEventHeaderId @id=@id output; select @id as id"
    $res = Invoke-SQLQuery -server $SQLServer -base $Database -text $SqlQuery
    $id = $res[0].id
	if ($id -eq $null) {$(throw "Id retrieval for bulk insert faild. Probably SQLServer problem.")}
    $rowcount = 0 #counter 
    $Totalrowcount = 0 #Global Counter
    foreach ($evt in $Events){
        if ($evt.index -gt $StartPosition){
			$EventID = [int]$($evt.EventID)
			$row = $tblEventHeaders.NewRow()
	        $row["id"] = $id
	        $row["Eventrecordid"] = $evt.Index
	        $Row["TimeGenerated"]=$evt.TimeGenerated
	        $SourceStr = [string]$($evt.Source)
			$EntryTypeStr = [string]$($evt.EntryType)
			if($Sources.keys -contains $SourceStr)
				{$SourceID = $Sources[$evt.Source]}
			else
				{
				$SourceID = Add-ItemValue -tblname Sources -KeyName SourceID -ValName SourceName -Value $evt.Source
				$Sources[$evt.Source] = $SourceID
				}
			$Row["SourceID"] = $SourceID
	        if($EntryTypes.keys -contains $EntryTypeStr)
				{$EntryTypeID = $EntryTypes[$EntryTypeStr]}
			else
				{
				$EntryTypeID = Add-ItemValue -tblname EntryTypes -KeyName EntryTypeID -ValName EntryTypeName -Value $evt.EntryType
				$EntryTypes[$evt.EntryType] = $EntryTypeID
				}	        
			$Row["EntryTypeID"] = $EntryTypeID
	        $Row["UserName"] = $evt.UserName
	        $Row["ComputerID"] = $ComputerID
	        $Row["Eventid"] = $EventID
	        $Row["CategoryNumber"] = $evt.CategoryNumber
			if ($KnownEventIds -notcontains $EventID) {$Row["Message"] = $evt.message}
	        $tblEventHeaders.Rows.Add($row)
	        for ($i = 0; $i -lt $evt.ReplacementStrings.count; $i++)
	            {
	            $row = $tblProperties.NewRow()
	            $Row["EventHeaderId"] = $id
	            $Row["PropertyNumber"] = $i+1
	            $Row["Value"] = $evt.ReplacementStrings[$i].tostring()
	            $tblProperties.Rows.Add($row)
	            }
	        $rowcount++
	        $id++
	        $Totalrowcount++
	        #Write Block to DB 
	        if ($rowcount -ge $Blocksize){
	            #Start transaction
	            $tran = $Connection.BeginTransaction("Data Block Insert")
	            $bulkCopyEvt = new-object Data.SqlClient.SqlBulkCopy($Connection, $BulkCopyOptions,$tran)    #Create SqlBulkCopy object
	            $bulkCopyEvt.DestinationTableName = "dbo.EventHeaders"                           #Assign Destination Table
	            $bulkCopyEvt.BulkCopyTimeout = 120
	            $bulkCopyProp = new-object Data.SqlClient.SqlBulkCopy($Connection, $BulkCopyOptions,$tran)    #Create SqlBulkCopy object
	            $bulkCopyProp.DestinationTableName = "dbo.Properties"                           #Assign Destination Table
	            $bulkCopyProp.BulkCopyTimeout = 120
	            $bulkCopyEvt.WriteToServer($tblEventHeaders.CreateDataReader())  #Write data block to DB
	            $bulkCopyProp.WriteToServer($tblProperties.CreateDataReader())  #Write data block to DB
	            $tblEventHeaders.clear() #Clear table to release memory
	            $tblProperties.clear() #Clear table to release memory
	            $rowcount=0    #Reset Row number
	            $res = Invoke-SQLQuery -server $SQLServer -base $Database -text $SqlQuery
	            $id = $res[0].id
				if ($id -eq $null) {$(throw "Id retrieval for bulk insert faild. Probably SQLServer problem.")}
	            $tran.commit()
	            }
			}
		}
    #Write rest of data to DB
    $tran = $Connection.BeginTransaction("Data Block Insert")
    $bulkCopyEvt = new-object Data.SqlClient.SqlBulkCopy($Connection, $BulkCopyOptions,$tran)    #Create SqlBulkCopy object
    $bulkCopyEvt.DestinationTableName = "dbo.EventHeaders"                           #Assign Destination Table
    $bulkCopyEvt.BulkCopyTimeout = 120
    $bulkCopyProp = new-object Data.SqlClient.SqlBulkCopy($Connection, $BulkCopyOptions,$tran)    #Create SqlBulkCopy object
    $bulkCopyProp.DestinationTableName = "dbo.Properties"                           #Assign Destination Table
    $bulkCopyProp.BulkCopyTimeout = 120
    $bulkCopyEvt.WriteToServer($tblEventHeaders.CreateDataReader())  #Write data block to DB
    $bulkCopyProp.WriteToServer($tblProperties.CreateDataReader())  #Write data block to DB
    $tran.commit()
	$connection.close()
	"$Totalrowcount records from log $Logname successfully written to DB" | Out-LogFile $Logfile -Append
	}
Catch
    {
    if ($tran.connection) {$tran.rollback()}
    if ($connection) {$connection.close()}
    "$_" | Out-LogFile $logfile -Append
    }
"Export finished" | Out-LogFile $Logfile -Append
"====================    Last Line    ====================" | Out-LogFile $Logfile -Append