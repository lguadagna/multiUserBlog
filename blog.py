import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'LisaGuadagna'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    # lmg added user 
    response.out.write('<b>' + post.subject + '</b>' + post.user + '<br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Wholesome ideas for you and the planet')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    
    @classmethod
    def get_name(self):
        return self.name

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    user = db.StringProperty()
    likes = db.RatingProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
  #  user=blog_key()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
    
    def upvote(self):
        p = self
        if p.likes >= 1: 
            p.likes = p.likes + 1
        else:
            p.likes = 1
        p.put()
  
class Comment(db.Model):
    post_reference = db.StringProperty(required = True)
    user = db.StringProperty()
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True) # current time 
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", p = self)
   

class BlogFront(BlogHandler):
    def get(self):
        #posts = greetings = Post.all().order('-created')
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        comments = db.GqlQuery(  "select *  from Comment order by created desc ") 
 
        self.render('front.html', posts = posts , comments= comments)
        # include comments on the front page also ...
     

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = post.subject
        comments = db.GqlQuery(  "select *  from Comment where post_reference = :subject  order by created desc ", subject=subject ) 
 
        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post, comments= comments, post_id = subject)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        # lmg - set the user of the post
        user = self.user.name
        

        if subject and content:
            # lmg added user
            p = Post(parent = blog_key(), subject = subject, content = content, user=user, likes=1, BlogHandler=BlogHandler)
            # this is storing the data in the database
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)
# end NewPost(BlogHandler)

class CommentPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key) 
        if self.user:         
            self.render("commentpost.html", subject=post.subject)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)   
        subject=post.subject

        content = self.request.get('content')
 
        # lmg - set the user of the post
        user = self.user.name
        

        if content:
            #post_reference 
            #user 
            #content 
            #created 
            c = Comment(parent = blog_key(), post_reference = subject, content = content, user=user, BlogHandler=BlogHandler)
            # this is storing the data in the database
            c.put()
            self.redirect('/' )
        else:
            error = "content, please!"
            self.render("commentpost.html", content=content, error=error)
# end CommentPost(BlogHandler)



class EditPost(BlogHandler):
    #retreive values p.post_id
    def get(self, post_id):
        # if logged in ..
        if not self.user:         
            self.redirect("/login")
            
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        
        if not post:
            self.error(404)
            return
        
        # not sure this works/ after get post and check 
        if self.user.name == post.user :
            subject = post.subject
            content = post.content
            # lmg - set the user of the post
            user = self.user
            self.render("newpost.html", subject=subject, content=content)
        else:
            error = "you can only edit your own posts"
            #self.render("/front.html", error=error)
            self.redirect("/", error=error)

            
    # post required for form input             
    def post(self, post_id):
            if not self.user:
                self.redirect('/login.html')
    
            subject = self.request.get('subject')
            content = self.request.get('content')
            # lmg - set the user of the post
            user = self.user.name
            
    
            if subject and content:
                # lmg added user
                p = Post(parent = blog_key(), subject = subject, content = content, user=user, likes=1, BlogHandler=BlogHandler)
                # this is storing the data in the database
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject, content=content, error=error)       
                
# end EditPost(BlogHandler)

class LikePost(BlogHandler):
    #retreive values p.post_id
    def get(self, post_id):
        # if user is logged in and not the poster...
        
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        post.upvote()
        self.redirect('/') # this really should update page dom

    #def post(self):
        
# end LikePost(BlogHandler)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError
# end Signup(BlogHandler)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')
# end Register(Signup)

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)
# end Login(BlogHandler)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/welcome', Welcome),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/newcomment/([0-9]+)', CommentPost),
                               ('/blog/like/([0-9]+)', LikePost)
                               ],
                              debug=True)
