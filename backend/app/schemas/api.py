from pydantic import BaseModel, Field
class LoginIn(BaseModel): email:str; password:str
class InvestigationIn(BaseModel): case_name:str=Field(min_length=1,max_length=120); description:str=''
