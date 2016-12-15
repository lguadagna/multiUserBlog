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
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

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
    #   """
    #   BlogHandler: request hangler for html
    #    Args:
    #       webapp2.RequestHandler
    #    Returns:
    #       nothing """

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
        self.write('Wholesome ideas for you and the environment')

# user stuff


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def get_name(self):
        return self.name

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user = db.StringProperty()
    likes = db.RatingProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    def upvote(self, currentUser):
        p = self
        u = currentUser
        # count number of likes in db on this post and with current logged in
        # user
        all_likes = db.GqlQuery("select * from Like where user= :user \
                                and post_reference= :post_ref",
                                user=u, post_ref=p.subject)
        # update likes attribute on post
        if all_likes.count() < 1:
            l = Like(post_reference=p.subject, user=u)
            l.put()
            p.likes = p.likes + 1
            p.put()


class Like(db.Model):
    post_reference = db.StringProperty(required=True)
    user = db.StringProperty()


class Comment(db.Model):
    post_reference = db.StringProperty(required=True)
    user = db.StringProperty()
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)  # current time

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", p=self)


class BlogFront(BlogHandler):

    def get(self):
        # posts = greetings = Post.all().order('-created')
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        comments = db.GqlQuery("select *  from Comment order by created desc ")
        self.render('front.html', posts=posts, comments=comments)


class PostPage(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = post.subject
        s = db.GqlQuery("select * from Comment where post_reference= :subject \
                        order by created desc ",
                        subject=subject)
        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post, comments=s, post_id=subject)


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            # task is to show or not show the delete button on this page
            self.render("newpost.html", task="new")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')
            return

        subject = self.request.get('subject')
        content = self.request.get('content')
        # lmg - set the user of the post
        user = self.user.name

        if subject and content:
            # lmg added user
            p = Post(parent=blog_key(), subject=subject, content=content,
                     user=user, likes=0, BlogHandler=BlogHandler)
            p.put()
            self.redirect("/")
        else:
            # storing the data in the database
            self.redirect('/blog/%s' % str(p.key().id()))
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject, content=content,
                error=error, task="new")
# end NewPost(BlogHandler)


class CommentPost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            return self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user:
            self.render("commentpost.html", subject=post.subject)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = post.subject
        content = self.request.get('content')
        # lmg - set the user of the post
        user = self.user.name

        if content:
            # post_reference
            # user
            # content
            # created
            c = Comment(parent=blog_key(), post_reference=subject,
                        content=content, user=user, BlogHandler=BlogHandler)

            # this is storing the data in the database
            c.put()
            self.redirect('/')
        else:
            error = "content, please!"
            self.render("commentpost.html", content=content, error=error)
# end CommentPost(BlogHandler)

# Delete Post


class DeletePost(BlogHandler):
    # retreive values p.post_id

    def get(self, post_id):
        # user login block from Comment
        if post_id == "":
            self.redirect("/")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return

        if self.user:   # if user logged in
            # not sure this works
            if self.user.name == post.user:
                db.delete(key)
                error = "blog entry deleted "

            else:
                error = "you are loggeed in as: %s, post is from %s " % (
                    self.user.name, post.user)
            # we need to query to display a good front page
            posts = db.GqlQuery(
                "select * from Post order by created desc limit 10")
            comments = db.GqlQuery(
                "select *  from Comment order by created desc ")

            self.redirect("/")
        # if not self.user....
        else:
            self.redirect("/login")

    # post required for form input
    def post(self, post_id):
        if post_id == "":
            self.redirect("/")
        if not self.user:
            self.redirect('/login.html')
            return

        self.redirect('/')

# end DeletePost(BlogHandler)


class EditPost(BlogHandler):
    # retreive values p.post_id

    def get(self, post_id):
        # user login block from Comment
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return

        if self.user:   # if user logged in
            # not sure this works
            if self.user.name == post.user:
                subject = post.subject
                content = post.content
                # lmg - set the user of the post
                user = self.user
                self.render(
                    "newpost.html", subject=subject, content=content,
                    post_id=post_id, task="edit")
            else:
                # we need to query to display a good front page
                posts = db.GqlQuery(
                    "select * from Post order by created desc limit 10")
                comments = db.GqlQuery(
                    "select *  from Comment order by created desc ")

                error = "you can only edit your own posts "
                self.render(
                    'front.html', posts=posts, comments=comments, error=error)

        else:
            self.redirect("/login")

    # post required for form input
    def post(self, post_id):
     # user login block from Comment
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login.html')
            return

        if self.user.name == post.user:

            subject = self.request.get('subject')
            content = self.request.get('content')
            # lmg - set the user of the post
            user = self.user.name
            if subject and content:
                post.subject = subject
                post.content = content
                # this is storing the data in the database
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = "subject and content, please!"
                self.render(
                    "newpost.html", subject=subject, content=content,
                    error=error)

# end EditPost(BlogHandler)


class EditComment(BlogHandler):
    # retreive values p.post_id

    def get(self, post_id):
        # user login block from Comment
        key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
        comment = db.get(key)
        if not comment:
            self.error(404)
            return

        if self.user:   # if user logged in
            # not sure this works
            if self.user.name == comment.user:
                content = comment.content
                # lmg - set the user of the post
                user = self.user
                self.render(
                    "commentpost.html", content=content,
                    post_id=post_id, task="edit")
            else:
                # we need to query to display a good front page
                posts = db.GqlQuery(
                    "select * from Post order by created desc limit 10")
                comments = db.GqlQuery(
                    "select *  from Comment order by created desc ")

                error = "you can only edit your own comments "
                self.render(
                    'front.html', posts=posts, comments=comments, error=error)

        else:
            self.redirect("/login")

    # post required for form input
    def post(self, comment_id):
     # user login block from Comment
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        #post_ref = comment.subject
        # how to refernce post with key: p.key().id())
        #post = db.GqlQuery("select * from Post where key = :post_ref", post_ref=post_ref)
        # if not post:
        #     self.error(404)
        #     return
        # subject = post.subject
        # if not comment:
        #     self.error(404)
        #     return

        if not self.user:
            self.redirect('/login.html')
            return

        if self.user.name == comment.user:

            content = self.request.get('content')
            # lmg - set the user of the post
            user = self.user.name
            if content:
                comment.content = content
                # this is storing the data in the database
                comment.put()
                self.redirect('/')
            else:
                error = "content, please!"
                self.render(
                    "commentpost.html", subject=subject, content=content,
                    error=error)

# end EditComment(BlogHandler)


class LikePost(BlogHandler):
    # retreive values p.post_id

    def get(self, post_id):
        if self.user:
             # if user is logged in and not the poster...
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
        else:
            self.redirect("/login")
            return

        # not sure this works/ after get post and check
        if self.user.name == post.user:
            # query so you get a good front page
            posts = db.GqlQuery(
                "select * from Post order by created desc limit 10")
            comments = db.GqlQuery(
                "select *  from Comment order by created desc ")

            error = "you ( " + self.user.name + \
                ") can not like posts by " + post.user
            self.render(
                "/front.html", posts=posts, comments=comments, error=error)
            return
            #self.redirect("/", error=error)

        if not post:
            self.error(404)
            return
        post.upvote(self.user.name)
        self.redirect('/')  # this really should update page dom

    # def post(self):

# end LikePost(BlogHandler)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


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

        params = dict(username=self.username,
                      email=self.email)

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
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
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
            self.render('login-form.html', error=msg)
# end Login(BlogHandler)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/blog')


class Welcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
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
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/newcomment/([0-9]+)', CommentPost),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/like/([0-9]+)', LikePost)
                               ],
                              debug=True)
