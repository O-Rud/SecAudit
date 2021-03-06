USE [master]
GO
/****** Object:  Database [SecAudit]    Script Date: 15.03.2016 11:14:24 ******/
CREATE DATABASE [SecAudit]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'SecAudit', FILENAME = N'C:\SQLServer\DBs\SecAudit.mdf' , SIZE = 102400KB , MAXSIZE = UNLIMITED, FILEGROWTH = 102400KB )
 LOG ON 
( NAME = N'SecAudit_log', FILENAME = N'C:\SQLServer\DBs\SecAudit_log.ldf' , SIZE = 478472KB , MAXSIZE = 2048GB , FILEGROWTH = 10%)
GO
ALTER DATABASE [SecAudit] SET COMPATIBILITY_LEVEL = 100
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [SecAudit].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [SecAudit] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [SecAudit] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [SecAudit] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [SecAudit] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [SecAudit] SET ARITHABORT OFF 
GO
ALTER DATABASE [SecAudit] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [SecAudit] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [SecAudit] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [SecAudit] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [SecAudit] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [SecAudit] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [SecAudit] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [SecAudit] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [SecAudit] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [SecAudit] SET  DISABLE_BROKER 
GO
ALTER DATABASE [SecAudit] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [SecAudit] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [SecAudit] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [SecAudit] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [SecAudit] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [SecAudit] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [SecAudit] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [SecAudit] SET RECOVERY SIMPLE 
GO
ALTER DATABASE [SecAudit] SET  MULTI_USER 
GO
ALTER DATABASE [SecAudit] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [SecAudit] SET DB_CHAINING OFF 
GO
ALTER DATABASE [SecAudit] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [SecAudit] SET TARGET_RECOVERY_TIME = 0 SECONDS 
GO
ALTER DATABASE [SecAudit] SET DELAYED_DURABILITY = DISABLED 
GO
USE [SecAudit]
GO
/****** Object:  UserDefinedFunction [dbo].[AccessMask2Accesses]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [dbo].[AccessMask2Accesses]
(
	@AccessMask bigint
)
RETURNS nvarchar(max)
AS
BEGIN
	DECLARE @Accesses VARCHAR(8000) 
	SELECT @Accesses = COALESCE(@Accesses + ', ', '') + [description]
	FROM AccessMasks where (@AccessMask & maskvalue) <> 0
	RETURN @Accesses

END

GO
/****** Object:  Table [dbo].[AccessMasks]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AccessMasks](
	[MaskValue] [bigint] NOT NULL,
	[Description] [nvarchar](100) NOT NULL,
 CONSTRAINT [PK_AccessMasks] PRIMARY KEY CLUSTERED 
(
	[MaskValue] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Computers]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Computers](
	[ComputerID] [int] IDENTITY(1,1) NOT NULL,
	[ComputerName] [nvarchar](50) NOT NULL,
 CONSTRAINT [PK_Computers] PRIMARY KEY CLUSTERED 
(
	[ComputerID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Conf]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Conf](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[PropType] [nvarchar](50) NOT NULL,
	[PropName] [nvarchar](50) NOT NULL,
	[PropValue] [nvarchar](50) NOT NULL,
 CONSTRAINT [PK_Conf] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[CriticalGroups]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CriticalGroups](
	[Name] [nvarchar](100) NOT NULL,
 CONSTRAINT [PK_CriticalGroups] PRIMARY KEY CLUSTERED 
(
	[Name] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[EntryTypes]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EntryTypes](
	[EntryTypeID] [int] IDENTITY(1,1) NOT NULL,
	[EntryTypeName] [nvarchar](50) NOT NULL,
 CONSTRAINT [PK_EntryTypes] PRIMARY KEY CLUSTERED 
(
	[EntryTypeID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[EventHeaders]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EventHeaders](
	[id] [bigint] NOT NULL,
	[Eventrecordid] [bigint] NOT NULL,
	[TimeGenerated] [datetime] NOT NULL,
	[SourceID] [int] NULL,
	[EntryTypeID] [int] NULL,
	[UserName] [nvarchar](50) NULL,
	[ComputerID] [int] NULL,
	[EventId] [int] NOT NULL,
	[Message] [nvarchar](max) NULL,
	[CategoryNumber] [int] NULL,
 CONSTRAINT [PK_EventHeaders] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[KnownEventIDs]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[KnownEventIDs](
	[EventID] [int] NOT NULL,
	[Description] [nvarchar](200) NOT NULL,
	[MessageTemplate] [nvarchar](2000) NULL,
 CONSTRAINT [PK_KnownEventIDs] PRIMARY KEY CLUSTERED 
(
	[EventID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[LastIDs]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LastIDs](
	[RecID] [int] IDENTITY(1,1) NOT NULL,
	[IDName] [nvarchar](50) NOT NULL,
	[IDValue] [bigint] NOT NULL,
 CONSTRAINT [PK_LastIDs] PRIMARY KEY CLUSTERED 
(
	[RecID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Properties]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Properties](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[EventHeaderId] [bigint] NOT NULL,
	[PropertyNumber] [int] NOT NULL,
	[Value] [nvarchar](max) NOT NULL,
 CONSTRAINT [PK_Parameters] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Sources]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Sources](
	[SourceID] [int] IDENTITY(1,1) NOT NULL,
	[SourceName] [nvarchar](200) NULL,
 CONSTRAINT [PK_Sources] PRIMARY KEY CLUSTERED 
(
	[SourceID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  View [dbo].[AccountCreateEvents]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[AccountCreateEvents]
AS
SELECT		e.id,
			e.TimeGenerated,
			CASE p1.[value]
				WHEN '' THEN p3.[value]
				ELSE p2.value + '\' + p1.value
			END AS Target, 
			CASE p5.[value]
				WHEN '' THEN p4.[value]
				ELSE p6.value + '\' + p5.value
			END AS Operator,
			et.EntryTypeName AS EntryType
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4720)


GO
/****** Object:  View [dbo].[AccountDeleteEvents]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[AccountDeleteEvents]
AS
SELECT		e.id,
			e.TimeGenerated,
			CASE p1.[value]
				WHEN '' THEN p3.[value]
				ELSE p2.value + '\' + p1.value
			END AS Target, 
			CASE p5.[value]
				WHEN '' THEN p4.[value]
				ELSE p6.value + '\' + p5.value
			END AS Operator,
			et.EntryTypeName AS EntryType
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4726)


GO
/****** Object:  View [dbo].[AccountDisableAttempts]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE VIEW [dbo].[AccountDisableAttempts]
AS
SELECT		e.id,
			e.TimeGenerated,
			CASE p1.[value]
				WHEN '' THEN p3.[value]
				ELSE p2.value + '\' + p1.value
			END AS Target, 
			CASE p5.[value]
				WHEN '' THEN p4.[value]
				ELSE p6.value + '\' + p5.value
			END AS Operator,
			et.EntryTypeName AS EntryType
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4725)



GO
/****** Object:  View [dbo].[AccountEnableAttempts]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[AccountEnableAttempts]
AS
SELECT		e.id,
			e.TimeGenerated,
			CASE p1.[value]
				WHEN '' THEN p3.[value]
				ELSE p2.value + '\' + p1.value
			END AS Target, 
			CASE p5.[value]
				WHEN '' THEN p4.[value]
				ELSE p6.value + '\' + p5.value
			END AS Operator,
			et.EntryTypeName AS EntryType
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4722)



GO
/****** Object:  View [dbo].[AccountPasswordResetAttempts]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[AccountPasswordResetAttempts]
AS
SELECT		e.id,
			e.TimeGenerated,
			CASE p1.[value]
				WHEN '' THEN p3.[value]
				ELSE p2.value + '\' + p1.value
			END AS Target, 
			CASE p5.[value]
				WHEN '' THEN p4.[value]
				ELSE p6.value + '\' + p5.value
			END AS Operator,
			et.EntryTypeName AS EntryType
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4724)



GO
/****** Object:  View [dbo].[AllAccountMgmtEvents]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[AllAccountMgmtEvents]
AS
SELECT	e.id,
		e.TimeGenerated,
		CASE p1.[value]
			WHEN '' THEN p3.[value]
			ELSE p2.value + '\' + p1.value
		END AS Target, 
		CASE p5.[value]
			WHEN '' THEN p4.[value]
			ELSE p6.value + '\' + p5.value
		END AS Operator, 
		case e.eventid
			when 4720 then 'Create'
			when 4722 then 'Enable'
			when 4724 then 'PwdReset'
			when 4725 then 'Disable'
			when 4726 then 'Delete'
		end as Action,
		et.EntryTypeName AS EntryType
FROM	dbo.EventHeaders AS e LEFT OUTER JOIN
        dbo.entryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT OUTER JOIN
        dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
        dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
        dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
        dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
        dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
        dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId in (4720,4722,4724,4725,4726))


GO
/****** Object:  View [dbo].[AllGroupMgmtEvents]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[AllGroupMgmtEvents]
AS
SELECT	e.id,
		e.TimeGenerated AS Eventtime,
		p2.Value + '\' + p1.Value AS [Group],
		CASE
			WHEN e.[eventid] IN (4727, 4730) THEN 'Global Security'
			WHEN e.[eventid] IN (4731, 4734) THEN 'Local Security'
			WHEN e.[eventid] IN (4754 ,4758) THEN 'Universal Security'
			WHEN e.[eventid] IN (4749, 4753) THEN 'Global Distribution'
			WHEN e.[eventid] IN (4744, 4748) THEN 'Local Distribution'
			WHEN e.[eventid] IN (4759, 4763) THEN 'Universal Distribution'
		END AS Grouptype,
		p6.Value + '\' + p5.Value AS Operator,
		CASE
			WHEN e.[eventid] IN (4727, 4731, 4754, 4749, 4744, 4759) THEN 'Create'
			WHEN e.[eventid] IN (4730, 4734, 4758, 4748, 4753, 4763) THEN 'Delete'
		END AS Action,
		et.EntryTypeName AS EntryType,
		c.Computername
FROM	dbo.EventHeaders AS e LEFT OUTER JOIN
		dbo.computers AS c on e.ComputerID = c.ComputerID LEFT OUTER JOIN
		dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT OUTER JOIN
		dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
		dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
		dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
		dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId IN (4727, 4730, 4731, 4734, 4754, 4758, 4744, 4748, 4749, 4753, 4759, 4763))


GO
/****** Object:  View [dbo].[FileAccessEvents]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[FileAccessEvents]
AS
SELECT	e.id,
		e.TimeGenerated as EventTime,
		p7.[value] ObjectName, 
		CASE p2.[value]
			WHEN '' THEN p1.[value]
			ELSE p3.value + '\' + p2.value
		END AS Operator,
		p10.Value AS AccessMask,
		am.description AS access,
		et.EntryTypeName AS EntryType,
		c.ComputerName
FROM	dbo.EventHeaders AS e LEFT OUTER JOIN
		dbo.Computers AS c on c.ComputerID = e.ComputerID Left join
        dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT JOIN
        dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT JOIN
        dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT JOIN
        dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT JOIN
        dbo.Properties AS p7 ON e.id = p7.EventHeaderId AND p7.PropertyNumber = 7 LEFT JOIN
        dbo.Properties AS p10 ON e.id = p10.EventHeaderId AND p10.PropertyNumber = 10 LEFT JOIN
        dbo.AccessMasks as am on ((p10.Value & am.maskvalue) <> 0)
WHERE     (e.EventId = 4663)


GO
/****** Object:  View [dbo].[FileAccessEvents2]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[FileAccessEvents2]
AS
SELECT	e.id,
		e.TimeGenerated as EventTime,
		p7.[value] ObjectName, 
		CASE p2.[value]
			WHEN '' THEN p1.[value]
			ELSE p3.value + '\' + p2.value
		END AS Operator,
		p10.Value AS AccessMask,
		dbo.AccessMask2Accesses(p10.value) AS access,
		et.EntryTypeName as EntryType,
		c.ComputerName

FROM	dbo.EventHeaders AS e LEFT JOIN
		dbo.Computers AS c on c.ComputerID = e.ComputerID Left Join
        dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT JOIN
        dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT JOIN
        dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT JOIN
        dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT JOIN
        dbo.Properties AS p7 ON e.id = p7.EventHeaderId AND p7.PropertyNumber = 7 LEFT JOIN
        dbo.Properties AS p10 ON e.id = p10.EventHeaderId AND p10.PropertyNumber = 10
WHERE     (e.EventId = 4663)


GO
/****** Object:  View [dbo].[GetSDChanges]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[GetSDChanges]
AS
SELECT	e.id,
		e.TimeGenerated as EventTime,
		p7.[value] ObjectName, 
		CASE p2.[value]
			WHEN '' THEN p1.[value]
			ELSE p3.value + '\' + p2.value
		END AS Operator,
		p9.Value AS OriginalSD,
		p10.Value AS NewSD,
		et.EntryTypeName as EntryType,
		c.ComputerName
FROM	dbo.EventHeaders AS e LEFT OUTER JOIN
		dbo.Computers AS c ON c.ComputerID = e.ComputerID Left Join
		dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT JOIN
		dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT JOIN
		dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT JOIN
		dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT JOIN
		dbo.Properties AS p7 ON e.id = p7.EventHeaderId AND p7.PropertyNumber = 7 LEFT JOIN
		dbo.Properties AS p9 ON e.id = p9.EventHeaderId AND p9.PropertyNumber = 9 LEFT JOIN
		dbo.Properties AS p10 ON e.id = p10.EventHeaderId AND p10.PropertyNumber = 10
WHERE (e.EventId = 4670)


GO
/****** Object:  View [dbo].[GroupCreateEvents]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[GroupCreateEvents]
AS
SELECT	e.id,
		e.TimeGenerated AS Eventtime,
		p2.Value + '\' + p1.Value AS [Group],
		CASE
			WHEN e.[eventid] = 4727 THEN 'Global Security'
			WHEN e.[eventid] = 4731 THEN 'Local Security'
			WHEN e.[eventid] = 4754 THEN 'Universal Security'
			WHEN e.[eventid] = 4749 THEN 'Global Distribution'
			WHEN e.[eventid] = 4744 THEN 'Local Distribution'
			WHEN e.[eventid] = 4759 THEN 'Universal Distribution'
		END AS Grouptype,
		p6.Value + '\' + p5.Value AS Operator, 
		et.EntryTypeName AS EntryType,
		c.ComputerName
FROM	dbo.EventHeaders AS e LEFT OUTER JOIN
		dbo.Computers AS c ON c.ComputerID = e.ComputerID Left Outer Join
        dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeId LEFT OUTER JOIN
        dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
        dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
        dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
        dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE	e.EventId IN (4727, 4731, 4754, 4744, 4749, 4759)


GO
/****** Object:  View [dbo].[GroupDeleteEvents]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[GroupDeleteEvents]
AS
SELECT	e.id,
		e.TimeGenerated AS Eventtime,
		p2.Value + '\' + p1.Value AS [Group],
		CASE
			WHEN e.[eventid] = 4730 THEN 'Global Security'
			WHEN e.[eventid] = 4734 THEN 'Local Security'
			WHEN e.[eventid] = 4758 THEN 'Universal Security'
			WHEN e.[eventid] = 4753 THEN 'Global Distribution'
			WHEN e.[eventid] = 4748 THEN 'Local Distribution'
			WHEN e.[eventid] = 4763 THEN 'Universal Distribution'
		END AS Grouptype,
		p6.Value + '\' + p5.Value AS Operator, 
		et.EntryTypeName AS EntryType,
		c.ComputerName
FROM	dbo.EventHeaders AS e LEFT OUTER JOIN
		dbo.Computers AS c on c.ComputerID = e.ComputerID LEFT OUTER JOIN
        dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT OUTER JOIN
        dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
        dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
        dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
        dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     e.EventId IN (4730, 4734, 4758, 4748, 4753, 4763)


GO
/****** Object:  View [dbo].[GroupMembershipChanges]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[GroupMembershipChanges]
AS
SELECT	e.id,
		e.TimeGenerated AS Eventtime,
		p4.Value + '\' + p3.Value AS [Group],
		CASE
			WHEN e.[eventid] IN (4728, 4729) THEN 'Global Security'
			WHEN e.[eventid] IN (4732, 4733) THEN 'Local Security'
			WHEN e.[eventid] IN (4756, 4757) THEN 'Universal Security'
			WHEN e.[eventid] IN (4746, 4747) THEN 'Global Distribution'
			WHEN e.[eventid] IN (4751, 4752) THEN 'Local Distribution'
			WHEN e.[eventid] IN (4761, 4762) THEN 'Universal Distribution'
		END AS Grouptype,
		p8.Value + '\' + p7.Value AS Operator, 
		CASE
			WHEN e.[eventid] IN (4728, 4732, 4756, 4746, 4751, 4761) THEN 'Add'
			WHEN e.[eventid] IN (4729, 4733, 4757, 4747, 4752, 4762) THEN 'Remove'
		END AS Action,
		p1.Value AS member,
		et.EntryTypeName as EntryType,
		c.ComputerName
FROM	dbo.EventHeaders AS e LEFT JOIN
		dbo.Computers AS c on c.ComputerID = e.ComputerID Left Join
        dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT  JOIN
        dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT JOIN
        dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT JOIN
        dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT JOIN
        dbo.Properties AS p7 ON e.id = p7.EventHeaderId AND p7.PropertyNumber = 7 LEFT JOIN
        dbo.Properties AS p8 ON e.id = p8.EventHeaderId AND p8.PropertyNumber = 8
WHERE     (e.EventId IN (4728, 4729, 4732, 4733, 4756, 4757, 4746, 4747, 4751, 4752, 4761, 4762))



GO
/****** Object:  View [dbo].[vwTGTRequests]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[vwTGTRequests]
AS
SELECT	e.id,
		e.TimeGenerated as EventTime,
		CASE p1.[value]
			WHEN '' THEN p3.[value]
			ELSE p2.value + '\' + p1.value
		END AS [User],
		p10.Value AS ClientIP,
		et.EntryTypeID
FROM	dbo.EventHeaders AS e LEFT JOIN
        dbo.EntryTypes AS et ON et.EntryTypeID = e.EntryTypeID LEFT JOIN
        dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT JOIN
        dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT JOIN
        dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT JOIN
        dbo.Properties AS p10 ON e.id = p10.EventHeaderId AND p10.PropertyNumber = 10
WHERE	(e.EventId = 4768)


GO
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (1, N'Read/List')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (2, N'WriteData (or AddFile)')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (4, N'Append/Create Subdirectory')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (8, N'Read extended attributes')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (16, N'Write extended attributes')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (32, N'Execute file/Traverse directory')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (64, N'Delete directory')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (128, N'ReadAttributes')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (256, N'WriteAttributes')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (65536, N'Delete')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (131072, N'Read ACL')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (262144, N'Write ACL')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (524288, N'Set Owner')
INSERT [dbo].[AccessMasks] ([MaskValue], [Description]) VALUES (1048576, N'Synchronizes access, allows a process to wait')
SET IDENTITY_INSERT [dbo].[Conf] ON 

INSERT [dbo].[Conf] ([Id], [PropType], [PropName], [PropValue]) VALUES (1, N'Script', N'BlockSize', N'100')
INSERT [dbo].[Conf] ([Id], [PropType], [PropName], [PropValue]) VALUES (2, N'Script', N'CalssicEventLogName', N'Security')
INSERT [dbo].[Conf] ([Id], [PropType], [PropName], [PropValue]) VALUES (4, N'Script', N'NewEventLogName', N'Microsoft-Windows-NTLM/Operational')
INSERT [dbo].[Conf] ([Id], [PropType], [PropName], [PropValue]) VALUES (5, N'Script', N'SQLTimeout', N'120')
INSERT [dbo].[Conf] ([Id], [PropType], [PropName], [PropValue]) VALUES (6, N'Script', N'SmtpServer', N'aspmx3.googlemail.com')
INSERT [dbo].[Conf] ([Id], [PropType], [PropName], [PropValue]) VALUES (7, N'Script', N'MailFrom', N'Secaudit@home24.de')
INSERT [dbo].[Conf] ([Id], [PropType], [PropName], [PropValue]) VALUES (8, N'Script', N'MailTo', N'oleksii.rud@home24.de')
SET IDENTITY_INSERT [dbo].[Conf] OFF
INSERT [dbo].[CriticalGroups] ([Name]) VALUES (N'*\Administrators')
INSERT [dbo].[CriticalGroups] ([Name]) VALUES (N'*\Domain Admins')
INSERT [dbo].[CriticalGroups] ([Name]) VALUES (N'*\Enterprise Admins')
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (1100, N'Eventlog service shutdown', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4616, N'System time changed', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4624, N'Logon', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4625, N'Account logon failed', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4634, N'Logoff', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4648, N'Logon attepmt using explicit credentials', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4672, N'Special privileges assigned to new logon', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4719, N'System audit policy was changed', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4720, N'User Account Create', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4722, N'User Account Enable', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4723, N'User Account Password Change Attempt', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4724, N'User Account Password Reset Attempt', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4725, N'User Account Disable', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4726, N'User Account Remove', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4727, N'Global Security Group Create
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4728, N'Global Security Group Members Add', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4729, N'Global Security Group Members Remove', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4730, N'Global Security Group Remove
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4731, N'Local Security Group Create
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4732, N'Local Security Group Members Add', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4733, N'Local Security Group Members Remove', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4734, N'Local Security Group Remove
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4735, N'Local Security Group Change', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4737, N'Global Security Group Change', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4738, N'User Account Change', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4740, N'User Account Locked Out', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4741, N'Computer Accout Created', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4742, N'Computer Account Change', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4743, N'Computer Account Remove', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4744, N'Local Distribution Group Create
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4745, N'Local Distribution Group Change', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4746, N'Local Distribution Group Members Add', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4747, N'Local Distribution Group Members Remove', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4748, N'Local Distribution Group Remove
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4749, N'Global Distribution Group Create
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4750, N'Global Distribution Group Change', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4751, N'Global Distribution Group Members Add', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4752, N'Global Distribution Group Members Remove', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4753, N'Global Distribution Group Remove
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4754, N'Universal Security Group Create
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4755, N'Universal Security Group Change', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4756, N'Universal Security Group Members Add', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4757, N'Universal Security Group Members Remove', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4758, N'Universal Security Group Remove
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4759, N'Universal Distribution Group Create
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4760, N'Universal Distribution Group Change', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4761, N'Universal Distribution Group Members Add', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4762, N'Universal Distribution Group Members Remove', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4763, N'Universal Distribution Group Remove
', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4764, N'Group Type Changed', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4765, N'SID History was added to an account', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4766, N'An attempt to add SID History to an account failed ', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4767, N'User Account Unlocked', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4768, N'TGT Request', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4769, N'TGS Request', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4770, N'TGS Renew', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4771, N'Kerberos pre-authentication failed', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4772, N'Kerberos authentication ticket request failed', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4773, N'TGS Request Fail', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4774, N'Account was mapped for logon', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4775, N'Account could not be mapped for logon', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4776, N'Credential validation', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4777, N'Credential validation failed', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4778, N'Session Reconnect', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4779, N'Session Disconnect', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4780, N'Admin members ACL Set', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4781, N'Account rename', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4782, N'Password hash accessed', NULL)
INSERT [dbo].[KnownEventIDs] ([EventID], [Description], [MessageTemplate]) VALUES (4794, N'DRSM Password Set Attempt', NULL)
/****** Object:  Index [_dta_index_EventHeaders_9_2073058421__K8_K1_3]    Script Date: 15.03.2016 11:14:24 ******/
CREATE NONCLUSTERED INDEX [_dta_index_EventHeaders_9_2073058421__K8_K1_3] ON [dbo].[EventHeaders]
(
	[EventId] ASC,
	[id] ASC
)
INCLUDE ( 	[TimeGenerated]) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
SET ANSI_PADDING ON

GO
/****** Object:  Index [_dta_index_Properties_23_613577224__K3_K2_4]    Script Date: 15.03.2016 11:14:24 ******/
CREATE NONCLUSTERED INDEX [_dta_index_Properties_23_613577224__K3_K2_4] ON [dbo].[Properties]
(
	[PropertyNumber] ASC,
	[EventHeaderId] ASC
)
INCLUDE ( 	[Value]) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
ALTER TABLE [dbo].[Properties]  WITH NOCHECK ADD  CONSTRAINT [FK_Properties_EventHeaders] FOREIGN KEY([EventHeaderId])
REFERENCES [dbo].[EventHeaders] ([id])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[Properties] CHECK CONSTRAINT [FK_Properties_EventHeaders]
GO
/****** Object:  StoredProcedure [dbo].[pr_GetEventHeaderId]    Script Date: 15.03.2016 11:14:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



CREATE procedure [dbo].[pr_GetEventHeaderId] 
	@id bigint output
as
begin
	set nocount on
	declare	@row_count bigint
	declare	@count int
	Select @count = cast(Propvalue as int) from Conf Where Propname = 'BlockSize'
	if	@count > 0
	begin
		begin tran
		begin try
			select	top 1 @id = IDValue
			from	dbo.LastIDs
			with (tablock xlock)
			where IDName = 'EventHeaderID'
			set	@row_count = @@rowcount

			if	@row_count = 0
			begin
				set	@id = 1
				insert	dbo.LastIDs(IDName,IDValue)
				values	('EventHeaderID', @id )
			end

			update	dbo.LastIDs
			set	IDValue = @id + @count
			where IDName = 'EventHeaderID'

			commit
		end try
		begin catch
			rollback
			return
		end catch
	end
	else if	@count is null
	begin
		raiserror ('Parameter @count cannot be NULL', 16, -1)
		return
	end
	else if	@count <= 0
	begin
		raiserror ('Parameter @count cannot be <= 0', 16, -1)
		return
	end
end




GO
USE [master]
GO
ALTER DATABASE [SecAudit] SET  READ_WRITE 
GO
