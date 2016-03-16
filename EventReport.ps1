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

#endregion Functions


#region Main Block
$encoding = [text.encoding]::unicode
#region LoadConfig
#Load from XML File
if ($ConfigFile -eq ""){
	$InvocationFolder = Split-path -Path $MyInvocation.mycommand.path -Parent
	$ConfigFile = Join-Path $InvocationFolder 'SecAuditConf.xml'
	}
if (-not (Test-Path $ConfigFile)) {throw "Config file $ConfigFile is inaccessable"}
$xml = [xml]$(gc $ConfigFile)
[string]$Server = $xml.config.server
[string]$DB = $xml.config.DB
[string]$LogFolder = $xml.config.LogFolder

#Load from SQL DB
$ErrorActionPreference = 'stop'
$SQLQuery = "Select PropName, PropValue from Conf where PropType = 'Reports' OR PropType = 'Common'"
$ConfRes = Invoke-SQLQuery -server $SQLServer -base $Database -text $SQLQuery
$sqlconf = @{}
$ConfRes | %{$sqlconf[$_.PropName]+=@($_.PropValue)}
[string]$SMTPServer = $sqlconf.SmtpServer
[string]$MailFrom = $sqlconf.MailFrom
[array]$MailTo = $sqlconf.MailTo
#endregion LoadConfig

$DocHeader=@"
<head>
<style type=`"text/css`">
table {
	border:1px solid black;
	width:100%;
	border-collapse:collapse;
	}
td,th,tr {
	padding:5px;
	border:1px solid black;
	}
.bg0{
	background-color: #ffffee;
}
.bg0red{
	background-color: #ffffee;
	color:red;
}
.bg0grayed{
	background-color: #ffffee;
	color:gray;
}
.bg1{
	background-color: #eeffff;
}
.bg1red{
	background-color: #eeffff;
	color:red;
}
.bg1grayed{
	background-color: #eeffff;
	color:gray;
}

</style>
</head>
<body>
"@
$tbl1header=@"
<table>
	<tr><th colspan=7>AD Group membership was changed</th></tr>
	<tr>
		<th>Time</th>
		<th>Group</th>
		<th>Group Type</th>
		<th>Operator</th>
		<th>Action</th>
		<th>Member</th>
		<th>EntryType</th>
	</tr>
"@
$tbl2header=@"
<table>
	<tr><th colspan=5>Active Directory User Account Management Events</th></tr>
	<tr>
		<th>Time</th>
		<th>Target Account</th>
		<th>Action</th>
		<th>Operator</th>
		<th>EntryType</th>
	</tr>
"@
$tbl3header=@"
<table>
	<tr><th colspan=6>Active Directory Group Management Events</th></tr>
	<tr>
		<th>Time</th>
		<th>Group</th>
		<th>Group Type</th>
		<th>Action</th>
		<th>Operator</th>
		<th>EntryType</th>
	</tr>
"@
$tblOtherHeader=@"
<table>
	<tr><th colspan=3>Other subscribed events.</th></tr>
	<tr>
		<th>Time</th>
		<th>Eventid</th>
		<th>Message</th>
	</tr>
"@
	
$message = $DocHeader+$tbl1header

try{
$Query = "Select name from CriticalGroups"
$CritGr = Invoke-SQLQuery -server $server -base $DB -text $query | %{$_.name}
$Query = "Select * from LastIDs where IDName = 'LastReportedEvent'"
$res = Invoke-SQLQuery -server $server -base $DB -text $Query
if ($res.Count -gt 0)
	{
	$id = $res[0].idvalue
	}
else
	{
	$Query = "INSERT LastIDs (IDName, IDValue) output inserted.* values('LastReportedEvent',0)"
	$res = Invoke-SQLQuery -server $server -base $DB -text $Query
	if ($res.Count -gt 0)
		{
		$id = $res[0].idvalue
		}
	else
		{
		throw "Failed to get last reported event"
		}
	}
$Query = "select Max(id) as maxid from EventHeaders"
$res = Invoke-SQLQuery -server $server -base $DB -text $query
$maxid = $res[0].maxid
$query = "select * from GroupMembershipChanges where id > @id order by eventtime"
$altstyle = $true
$OldTarget = ""
Invoke-SQLQuery -server $server -base $DB -text $query -params @{id = $id} | %{
    $datetime = $_.eventtime
    $group = $_.Group
    $operator = $_.Operator
    $member = $_.member
    $EntryType = $_.EntryType
    $grouptype = $_.GroupType
    $Action = $_.Action
	if ($OldTarget -ne $member) {$altstyle = -not $altstyle}
	$style="bg$([int]$altstyle)"
	$OldTarget = $member
	if ($Action  -eq 'Remove' -or $EntryType -eq 'FailureAudit') {$style+='grayed'}
	if ($CritGr -contains $group) {$style += 'red'}
    $Message += "<tr class=$style><td>$datetime</td><td>$group</td><td>$groupType</td><td>$operator</td><td>$action</td><td>$Member</td><td>$EntryType</td></tr>"
	}
$message += "
</table>&nbsp;"
$message += $tbl2header

$Query = "select * from [AllAccountMgmtEvents] where id > @id order by EventTime"
$altstyle = $true
$OldTarget = ""
Invoke-SQLQuery -server $server -base $DB -text $query -params @{id = $id} | %{
    $datetime = $_.EventTime
    $Target = $_.Target
    $operator = $_.Operator
	$action = $_.action
    $EntryType = $_.EntryType
    if ($OldTarget -ne $Target) {$altstyle = -not $altstyle}
	$style="bg$([int]$altstyle)"
	$OldTarget = $Target
	if ($EntryType -eq 'FailureAudit') {$style+='grayed'}
	$Message += "<tr class='$style'><td>$datetime</td><td>$Target</td><td>$action</td><td>$operator</td><td>$EntryType</td></tr>"
    }
$message += "</table>&nbsp;"

$message += $tbl3header
$altstyle = $true
$OldTarget = ""
$Query = "select * from AllGroupMgmtEvents where id > $id order by Eventtime"
Invoke-SQLQuery -server $server -base $DB -text $query | %{
    $datetime = $_.Eventtime
    $Target = $_.Group
	$grouptype = $_.grouptype
    $operator = $_.Operator
	$action = $_.action
    $EntryType = $_.EntryType
	if ($OldTarget -ne $Target) {$altstyle = -not $altstyle}
	$style="bg$([int]$altstyle)"
	$OldTarget = $Target
	if ($keywords -eq 'Audit Failure') {$style+='grayed'}
    $Message += "<tr class='$style'><td>$datetime</td><td>$Target</td><td>$grouptype</td><td>$action</td><td>$operator</td><td>$EntryType</td></tr>"
    }
$message += "</table>&nbsp;"

#$message += $tblOtherHeader

#$query = "select id, eventid, EventTime, message from Eventheaders where id > @id and eventid in (4765, 4766, 1102) "
#Invoke-SQLQuery -server $server -base $DB -text $query -params @{id=$id} | %{
#    $datetime = $_.EventTime
#    $eventid = $_.eventid
#    $msg = $_.Message
#    $Message += "<tr><td>$datetime</td><td>$Eventid</td><td>$Msg</td></tr>"
#	}
$Message += "</table></body>"
Send-MailMessage -To $mailto -Subject "AD Audit Report" -From $mailfrom -SmtpServer $SMTPServer -Body $message -BodyAsHtml -Encoding $encoding
}
catch {$_; Send-MailMessage -To $mailto -Subject "AD Audit Report Error" -From $mailfrom -SmtpServer $SMTPServer -Body $_ -Encoding $encoding}
$Query = "Update LastIDS Set IDValue = @maxid where IDName = 'LastReportedEvent'"
Invoke-SQLQuery -server $server -base $DB -text $Query -params @{maxid = $maxid}
#endregion Main Block