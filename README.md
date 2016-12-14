# multiUserBlog
Udacity project 


This project is hosted on google app engine at this address:

**https://multiuserblog-151616.appspot.com/**

If you want to run it yourself, download the code. 

You must install google app engine. 

after it is installed, use the Google Cloud SDK shell. Go to the directory the code is installed. 

To depoloy to cloud: 

`gcloud app deply` 
will install the code to your own version of the app engine. 

To test locally:

`dev_appserver.py .`

then you can use your browser to view locally at: 
http://localhost:8080

It uses jinja2 templates to serve the web pages. Data is stored with google app engine. 

