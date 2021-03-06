--------------------------------------------------------
--  文件已创建 - 星期三-一月-10-2018   
--------------------------------------------------------
--------------------------------------------------------
--  DDL for Table REFRESH_TOKEN
--------------------------------------------------------

  CREATE TABLE "REFRESH_TOKEN" 
   (	"ID" NUMBER(20,0), 
	"TOKEN_VALUE" VARCHAR2(200 BYTE), 
	"EXPIRATION" VARCHAR2(200 BYTE), 
	"USER_ID" VARCHAR2(200 BYTE), 
	"CLIENT_ID" VARCHAR2(200 BYTE)
   ) SEGMENT CREATION IMMEDIATE 
  PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT FLASH_CACHE DEFAULT CELL_FLASH_CACHE DEFAULT)
  TABLESPACE "USERS" ;
REM INSERTING into REFRESH_TOKEN
SET DEFINE OFF;
--------------------------------------------------------
--  DDL for Index REFRESH_TOKEN_PK
--------------------------------------------------------

  CREATE UNIQUE INDEX "REFRESH_TOKEN_PK" ON "REFRESH_TOKEN" ("ID") 
  PCTFREE 10 INITRANS 2 MAXTRANS 255 COMPUTE STATISTICS 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT FLASH_CACHE DEFAULT CELL_FLASH_CACHE DEFAULT)
  TABLESPACE "USERS" ;
--------------------------------------------------------
--  Constraints for Table REFRESH_TOKEN
--------------------------------------------------------

  ALTER TABLE "REFRESH_TOKEN" ADD CONSTRAINT "REFRESH_TOKEN_PK" PRIMARY KEY ("ID")
  USING INDEX PCTFREE 10 INITRANS 2 MAXTRANS 255 COMPUTE STATISTICS 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT FLASH_CACHE DEFAULT CELL_FLASH_CACHE DEFAULT)
  TABLESPACE "USERS"  ENABLE;
 
  ALTER TABLE "REFRESH_TOKEN" MODIFY ("ID" NOT NULL ENABLE);
