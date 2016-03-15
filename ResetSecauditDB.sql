use secaudit
delete properties
DBCC CHECKIDENT(properties, RESEED, 0);
delete eventheaders
delete entryTypes
DBCC CHECKIDENT(entryTypes, RESEED, 0);
delete computers
DBCC CHECKIDENT(computers, RESEED, 0);
delete sources
DBCC CHECKIDENT(sources, RESEED, 0);
delete LastIDs
DBCC CHECKIDENT(LastIDS, RESEED, 0);
