from google import auth

credentials, project = auth.default()
print(credentials.get_cred_info())
print(project)
