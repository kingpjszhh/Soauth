--------------------------------------------------------
--  �ļ��Ѵ��� - ������-һ��-10-2018   
--------------------------------------------------------
--------------------------------------------------------
--  DDL for Table CLIENT_DETAILS
--------------------------------------------------------

  CREATE TABLE "CLIENT_DETAILS" 
   (	"CLIENT_ID" VARCHAR2(200 BYTE), 
	"CLIENT_SECRET" VARCHAR2(200 BYTE), 
	"CLIENT_NAME" VARCHAR2(200 BYTE), 
	"CLIENT_URI" VARCHAR2(200 BYTE), 
	"LOGIN_URI" VARCHAR2(200 BYTE), 
	"SCOPE" VARCHAR2(200 BYTE), 
	"GRANT_TYPES" VARCHAR2(200 BYTE), 
	"ACCESS_TOKEN_VALIDITY" NUMBER(20,0), 
	"REFRESH_TOKEN_VALIDITY" NUMBER(20,0), 
	"DESCRIPTION" VARCHAR2(200 BYTE), 
	"CREATE_TIME" DATE, 
	"TOKENENDPOINTMETHOD" VARCHAR2(200 BYTE), 
	"REDIRECT_URI" VARCHAR2(200 BYTE)
   ) SEGMENT CREATION IMMEDIATE 
  PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT FLASH_CACHE DEFAULT CELL_FLASH_CACHE DEFAULT)
  TABLESPACE "USERS" ;
REM INSERTING into CLIENT_DETAILS
SET DEFINE OFF;
Insert into CLIENT_DETAILS (CLIENT_ID,CLIENT_SECRET,CLIENT_NAME,CLIENT_URI,LOGIN_URI,SCOPE,GRANT_TYPES,ACCESS_TOKEN_VALIDITY,REFRESH_TOKEN_VALIDITY,DESCRIPTION,CREATE_TIME,TOKENENDPOINTMETHOD,REDIRECT_URI) values ('testclient','test_secret','client_name','http','nul','openid,refresh_token','authorization_code',1,1,'description',to_date('03-1�� -18','DD-MON-RR'),null,'http://localhost:8089/client/oidc/authorize_callback_code');