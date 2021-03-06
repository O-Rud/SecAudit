USE [master]
GO
/****** Object:  Database [SecAudit]    Script Date: 11/16/2012 13:05:50 ******/
CREATE DATABASE [SecAudit] ON  PRIMARY 
( NAME = N'SecAudit', FILENAME = N'C:\SQLServer\DBs\SecAudit.mdf' , SIZE = 102400KB , MAXSIZE = UNLIMITED, FILEGROWTH = 102400KB )
 LOG ON 
( NAME = N'SecAudit_log', FILENAME = N'C:\SQLServer\DBs\SecAudit_log.ldf' , SIZE = 3828544KB , MAXSIZE = 2048GB , FILEGROWTH = 10%)
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
ALTER DATABASE [SecAudit] SET AUTO_CREATE_STATISTICS ON
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
ALTER DATABASE [SecAudit] SET  READ_WRITE
GO
ALTER DATABASE [SecAudit] SET RECOVERY SIMPLE
GO
ALTER DATABASE [SecAudit] SET  MULTI_USER
GO
ALTER DATABASE [SecAudit] SET PAGE_VERIFY CHECKSUM
GO
ALTER DATABASE [SecAudit] SET DB_CHAINING OFF
GO
USE [SecAudit]
GO
/****** Object:  Table [dbo].[EventHeaders_ID]    Script Date: 11/16/2012 13:05:52 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EventHeaders_ID](
	[new_id] [bigint] NOT NULL,
 CONSTRAINT [PK_EventHeaders_ID] PRIMARY KEY CLUSTERED 
(
	[new_id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[EventHeaders]    Script Date: 11/16/2012 13:05:52 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EventHeaders](
	[id] [bigint] NOT NULL,
	[Eventrecordid] [bigint] NOT NULL,
	[DateTime] [datetime] NOT NULL,
	[Source] [nvarchar](50) NOT NULL,
	[OpCode] [nvarchar](50) NOT NULL,
	[User] [nvarchar](50) NULL,
	[Computer] [nvarchar](50) NOT NULL,
	[EventId] [int] NOT NULL,
	[Message] [nvarchar](max) NOT NULL,
	[LogName] [nvarchar](50) NOT NULL,
	[TaskCategory] [nvarchar](50) NULL,
	[Level] [nvarchar](50) NULL,
 CONSTRAINT [PK_EventHeaders] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [_dta_index_EventHeaders_23_405576483__K7_2] ON [dbo].[EventHeaders] 
(
	[Computer] ASC
)
INCLUDE ( [Eventrecordid]) WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [_dta_index_EventHeaders_23_405576483__K8_K1_K3_7_9] ON [dbo].[EventHeaders] 
(
	[EventId] ASC,
	[id] ASC,
	[DateTime] ASC
)
INCLUDE ( [Computer],
[Message]) WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [_dta_index_EventHeaders_9_2073058421__K8_K1_3] ON [dbo].[EventHeaders] 
(
	[EventId] ASC,
	[id] ASC
)
INCLUDE ( [DateTime]) WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[CriticalGroups]    Script Date: 11/16/2012 13:05:52 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CriticalGroups](
	[Name] [nvarchar](100) NOT NULL,
 CONSTRAINT [PK_CriticalGroups] PRIMARY KEY CLUSTERED 
(
	[Name] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AccessMasks]    Script Date: 11/16/2012 13:05:52 ******/
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
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Properties]    Script Date: 11/16/2012 13:05:52 ******/
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
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [_dta_index_Properties_23_613577224__K3_K2_4] ON [dbo].[Properties] 
(
	[PropertyNumber] ASC,
	[EventHeaderId] ASC
)
INCLUDE ( [Value]) WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
/****** Object:  StoredProcedure [dbo].[pr_GetEventHeaderId]    Script Date: 11/16/2012 13:05:52 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		Fursov Pavel
-- Create date: 
-- Description:	
-- =============================================
CREATE procedure [dbo].[pr_GetEventHeaderId] 
	@count int = 1,
	@@id bigint output
as
begin
	set nocount on
	declare	@row_count bigint

	if	@count > 0
	begin
		begin tran
		begin try
			select	top 1 @@id = new_id
			from	dbo.EventHeaders_ID
			with (tablock xlock)

			set	@row_count = @@rowcount

			if	@row_count = 0
			begin
				set	@@id = 1 --начать с 1
				insert	dbo.EventHeaders_ID( new_id )
				values	( @@id )
			end

			update	dbo.EventHeaders_ID
			set	new_id = @@id + @count

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
/****** Object:  Table [dbo].[Keywords]    Script Date: 11/16/2012 13:05:52 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Keywords](
	[id] [bigint] IDENTITY(1,1) NOT NULL,
	[EventHeaderId] [bigint] NOT NULL,
	[Value] [nvarchar](50) NOT NULL,
 CONSTRAINT [PK_Keywords] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [_dta_index_Keywords_23_501576825__K2_K3] ON [dbo].[Keywords] 
(
	[EventHeaderId] ASC,
	[Value] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [_dta_index_Keywords_9_21575115__K3_K2] ON [dbo].[Keywords] 
(
	[Value] ASC,
	[EventHeaderId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
/****** Object:  UserDefinedFunction [dbo].[AccessMask2Accesses]    Script Date: 11/16/2012 13:05:53 ******/
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
/****** Object:  View [dbo].[vwTGTRequests]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vwTGTRequests]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime, CASE p1.[value] WHEN '' THEN p3.[value] ELSE p2.value + '\' + p1.value END AS [User], p10.Value AS ClientIP
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p10 ON e.id = p10.EventHeaderId AND p10.PropertyNumber = 10
WHERE     (e.EventId = 4768) AND (k.Value = 'Audit Success')
GO

/****** Object:  View [dbo].[GetSDChanges]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[GetSDChanges]
AS
SELECT e.id,
	e.DateTime,
	p7.[value] ObjectName, 
    CASE p2.[value] WHEN '' THEN p1.[value] ELSE p3.value + '\' + p2.value END AS Operator,
    p9.Value AS OriginalSD,
    p10.Value AS NewSD,
    k.Value AS keyword,
    e.Computer

FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p7 ON e.id = p7.EventHeaderId AND p7.PropertyNumber = 7 LEFT OUTER JOIN
                      dbo.Properties AS p9 ON e.id = p9.EventHeaderId AND p9.PropertyNumber = 9 LEFT OUTER JOIN
                      dbo.Properties AS p10 ON e.id = p10.EventHeaderId AND p10.PropertyNumber = 10
                     
WHERE     (e.EventId = 4670)
GO
/****** Object:  View [dbo].[Get-PasswordResetAttempts]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Get-PasswordResetAttempts]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime, CASE p1.[value] WHEN '' THEN p3.[value] ELSE p2.value + '\' + p1.value END AS Target, 
                      CASE p5.[value] WHEN '' THEN p4.[value] ELSE p6.value + '\' + p5.value END AS Operator, k.Value AS keyword
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4724)
ORDER BY keyword DESC, e.DateTime
GO

/****** Object:  View [dbo].[Get-GroupMembershipChanges]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Get-GroupMembershipChanges]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime AS Eventtime, p4.Value + '\' + p3.Value AS [Group], CASE WHEN e.[eventid] IN (4728, 4729) 
                      THEN 'Global Security' WHEN e.[eventid] IN (4732, 4733) THEN 'Local Security' WHEN e.[eventid] IN (4756, 4757) 
                      THEN 'Universal Security' WHEN e.[eventid] IN (4746, 4747) THEN 'Global Distribution' WHEN e.[eventid] IN (4751, 4752) 
                      THEN 'Local Distribution' WHEN e.[eventid] IN (4761, 4762) THEN 'Universal Distribution' END AS Grouptype, p8.Value + '\' + p7.Value AS Operator, 
                      CASE WHEN e.[eventid] IN (4728, 4732, 4756, 4746, 4751, 4761) THEN 'Add' WHEN e.[eventid] IN (4729, 4733, 4757, 4747, 4752, 4762) THEN 'Remove' END AS Action,
                       p1.Value AS member, k.Value AS keyword, e.Computer
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p7 ON e.id = p7.EventHeaderId AND p7.PropertyNumber = 7 LEFT OUTER JOIN
                      dbo.Properties AS p8 ON e.id = p8.EventHeaderId AND p8.PropertyNumber = 8
WHERE     (e.EventId IN (4728, 4729, 4732, 4733, 4756, 4757, 4746, 4747, 4751, 4752, 4761, 4762))
ORDER BY Eventtime DESC
GO
/****** Object:  View [dbo].[GetFileAccess2]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[GetFileAccess2]
AS
SELECT e.id,
	e.DateTime,
	p7.[value] ObjectName, 
    CASE p2.[value] WHEN '' THEN p1.[value] ELSE p3.value + '\' + p2.value END AS Operator,
    p10.Value AS AccessMask,
    dbo.AccessMask2Accesses(p10.value) AS access,
    k.Value AS keyword,
    e.Computer

FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p7 ON e.id = p7.EventHeaderId AND p7.PropertyNumber = 7 LEFT OUTER JOIN
                      dbo.Properties AS p10 ON e.id = p10.EventHeaderId AND p10.PropertyNumber = 10
                    
WHERE     (e.EventId = 4663)
GO
/****** Object:  View [dbo].[GetFileAccess]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[GetFileAccess]
AS
SELECT e.id,
	e.DateTime,
	p7.[value] ObjectName, 
    CASE p2.[value] WHEN '' THEN p1.[value] ELSE p3.value + '\' + p2.value END AS Operator,
    p10.Value AS AccessMask,
    am.description AS access,
    k.Value AS keyword,
    e.Computer

FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p7 ON e.id = p7.EventHeaderId AND p7.PropertyNumber = 7 LEFT OUTER JOIN
                      dbo.Properties AS p10 ON e.id = p10.EventHeaderId AND p10.PropertyNumber = 10 LEFT OUTER JOIN
                      dbo.AccessMasks as am on ((p10.Value & am.maskvalue) <> 0)
WHERE     (e.EventId = 4663)
GO
/****** Object:  View [dbo].[Get-DeleteGroupEvents]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Get-DeleteGroupEvents]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime AS Eventtime, p2.Value + '\' + p1.Value AS [Group], CASE WHEN e.[eventid] = 4730
                      THEN 'Global Security' WHEN e.[eventid] = 4734 THEN 'Local Security' WHEN e.[eventid] = 4758
                      THEN 'Universal Security' WHEN e.[eventid] = 4753 THEN 'Global Distribution' WHEN e.[eventid] = 4748
                      THEN 'Local Distribution' WHEN e.[eventid] = 4763 THEN 'Universal Distribution' END AS Grouptype, p6.Value + '\' + p5.Value AS Operator, 
                      k.Value AS keyword, e.Computer
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     e.EventId IN (4730, 4734, 4758, 4748, 4753, 4763)
ORDER BY Eventtime DESC
GO
/****** Object:  View [dbo].[Get-DeleteAccountEvents]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Get-DeleteAccountEvents]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime, CASE p1.[value] WHEN '' THEN p3.[value] ELSE p2.value + '\' + p1.value END AS Target, 
                      CASE p5.[value] WHEN '' THEN p4.[value] ELSE p6.value + '\' + p5.value END AS Operator, k.Value AS keyword
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4726)
ORDER BY keyword DESC, e.DateTime
GO
/****** Object:  View [dbo].[Get-CreateGroupEvents]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Get-CreateGroupEvents]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime AS Eventtime, p2.Value + '\' + p1.Value AS [Group], CASE WHEN e.[eventid] = 4727
                      THEN 'Global Security' WHEN e.[eventid] = 4731 THEN 'Local Security' WHEN e.[eventid] = 4754
                      THEN 'Universal Security' WHEN e.[eventid] = 4749 THEN 'Global Distribution' WHEN e.[eventid] = 4744
                      THEN 'Local Distribution' WHEN e.[eventid] = 4759 THEN 'Universal Distribution' END AS Grouptype, p6.Value + '\' + p5.Value AS Operator, 
                      k.Value AS keyword, e.Computer
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     e.EventId IN (4727, 4731, 4754, 4744, 4749, 4759)
ORDER BY Eventtime DESC
GO
/****** Object:  View [dbo].[Get-CreateDeleteGroupEvents]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Get-CreateDeleteGroupEvents]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime AS Eventtime, p2.Value + '\' + p1.Value AS [Group], CASE WHEN e.[eventid] IN (4727, 4730) 
                      THEN 'Global Security' WHEN e.[eventid] IN (4731, 4734) THEN 'Local Security' WHEN e.[eventid] IN (4754 ,4758) 
                      THEN 'Universal Security' WHEN e.[eventid] IN (4749, 4753) THEN 'Global Distribution' WHEN e.[eventid] IN (4744, 4748) 
                      THEN 'Local Distribution' WHEN e.[eventid] IN (4759, 4763) THEN 'Universal Distribution' END AS Grouptype, p6.Value + '\' + p5.Value AS Operator, 
                      CASE WHEN e.[eventid] IN (4727, 4731, 4754, 4749, 4744, 4759) THEN 'Create' WHEN e.[eventid] IN (4730, 4734, 4758, 4748, 4753, 4763) THEN 'Delete' END AS Action,
                      k.Value AS keyword, e.Computer
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId IN (4727, 4730, 4731, 4734, 4754, 4758, 4744, 4748, 4749, 4753, 4759, 4763))
ORDER BY Eventtime DESC
GO
/****** Object:  View [dbo].[Get-CreateAccountEvents]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Get-CreateAccountEvents]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime, CASE p1.[value] WHEN '' THEN p3.[value] ELSE p2.value + '\' + p1.value END AS Target, 
                      CASE p5.[value] WHEN '' THEN p4.[value] ELSE p6.value + '\' + p5.value END AS Operator, k.Value AS keyword
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4720)
ORDER BY keyword DESC, e.DateTime
GO
/****** Object:  View [dbo].[Get-AccountManagementEvents]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
Create VIEW [dbo].[Get-AccountManagementEvents]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime, CASE p1.[value] WHEN '' THEN p3.[value] ELSE p2.value + '\' + p1.value END AS Target, 
                      CASE p5.[value] WHEN '' THEN p4.[value] ELSE p6.value + '\' + p5.value END AS Operator, 
                      case e.eventid
                      when 4720 then 'Create'
                      when 4722 then 'Enable'
                      when 4724 then 'PwdReset'
                      when 4725 then 'Disable'
                      when 4726 then 'Delete' end as Action,
                      k.Value AS keyword
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId in (4720,4722,4724,4725,4726))
GO
/****** Object:  View [dbo].[Get-AccountEnableAttempts]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Get-AccountEnableAttempts]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime, CASE p1.[value] WHEN '' THEN p3.[value] ELSE p2.value + '\' + p1.value END AS Target, 
                      CASE p5.[value] WHEN '' THEN p4.[value] ELSE p6.value + '\' + p5.value END AS Operator, k.Value AS keyword
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4722)
ORDER BY keyword DESC, e.DateTime
GO

/****** Object:  View [dbo].[Get-AccountDisableAttempts]    Script Date: 11/16/2012 13:05:54 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Get-AccountDisableAttempts]
AS
SELECT     TOP (100) PERCENT e.id, e.DateTime, CASE p1.[value] WHEN '' THEN p3.[value] ELSE p2.value + '\' + p1.value END AS Target, 
                      CASE p5.[value] WHEN '' THEN p4.[value] ELSE p6.value + '\' + p5.value END AS Operator, k.Value AS keyword
FROM         dbo.EventHeaders AS e LEFT OUTER JOIN
                      dbo.Keywords AS k ON k.EventHeaderId = e.id LEFT OUTER JOIN
                      dbo.Properties AS p1 ON e.id = p1.EventHeaderId AND p1.PropertyNumber = 1 LEFT OUTER JOIN
                      dbo.Properties AS p2 ON e.id = p2.EventHeaderId AND p2.PropertyNumber = 2 LEFT OUTER JOIN
                      dbo.Properties AS p3 ON e.id = p3.EventHeaderId AND p3.PropertyNumber = 3 LEFT OUTER JOIN
                      dbo.Properties AS p4 ON e.id = p4.EventHeaderId AND p4.PropertyNumber = 4 LEFT OUTER JOIN
                      dbo.Properties AS p5 ON e.id = p5.EventHeaderId AND p5.PropertyNumber = 5 LEFT OUTER JOIN
                      dbo.Properties AS p6 ON e.id = p6.EventHeaderId AND p6.PropertyNumber = 6
WHERE     (e.EventId = 4725)
ORDER BY keyword DESC, e.DateTime
GO
/****** Object:  ForeignKey [FK_Properties_EventHeaders]    Script Date: 11/16/2012 13:05:52 ******/
ALTER TABLE [dbo].[Properties]  WITH NOCHECK ADD  CONSTRAINT [FK_Properties_EventHeaders] FOREIGN KEY([EventHeaderId])
REFERENCES [dbo].[EventHeaders] ([id])
GO
ALTER TABLE [dbo].[Properties] CHECK CONSTRAINT [FK_Properties_EventHeaders]
GO
/****** Object:  ForeignKey [FK_Keywords_EventHeaders]    Script Date: 11/16/2012 13:05:52 ******/
ALTER TABLE [dbo].[Keywords]  WITH NOCHECK ADD  CONSTRAINT [FK_Keywords_EventHeaders] FOREIGN KEY([EventHeaderId])
REFERENCES [dbo].[EventHeaders] ([id])
GO
ALTER TABLE [dbo].[Keywords] CHECK CONSTRAINT [FK_Keywords_EventHeaders]
GO
/****** Object:  Table [dbo].[CriticalGroups]    Script Date: 11/16/2012 13:14:44 ******/
INSERT [dbo].[CriticalGroups] ([Name]) VALUES (N'*\Administrators')
INSERT [dbo].[CriticalGroups] ([Name]) VALUES (N'*\Domain Admins')
INSERT [dbo].[CriticalGroups] ([Name]) VALUES (N'*\Enterprise Admins')
/****** Object:  Table [dbo].[AccessMasks]    Script Date: 11/16/2012 13:14:44 ******/
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
/****** Object:  Table [dbo].[EventHeaders_ID]    Script Date: 11/16/2012 13:16:32 ******/
--declare @newid bigint
--SELECT @newid = MAX(id)+1 from SecAuditDW.dbo.EventHeaders
--INSERT [dbo].[EventHeaders_ID] ([new_id]) VALUES (@newid)