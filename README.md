# Auth
**Auth addon for Simple MVC Framework**

This will help you to easily protect your site with an auth based system.

1) Copy Auth folder to your Helpers folder
2) Edit Setup.php important variables are SITE_NAME, EMAIL_FROM, BASE_URL, LOC
3) Special variables like ACTIVATION_ROUTE, RESET_PASSWORD_ROUTE, need each one a route
on Config.php, one for activating an account and one for reset the password, its value must 
be the same as the route defined.
4) Create a new database and import auth.sql using your prefered database client(phpmyadmin, heidysql) 
and execute it, this will create the tables activitylog, attempts, sessions, users.
 -Note: the connections to db should be setup inside the framework

**Usage**

- Create a private variable on your controller  and initialize it on __construct
``` 
use Core\View;
use Core\Controller;
use Helpers\Request as Request;

class Main extends Controller {

    private $auth;

    public function __construct() {
        parent::__construct();
        $this->auth = new \Helpers\Auth\Auth();
    }
    ....
    ....
``` 
**For using the following functions you must setup a route for each one on Config.php**

- Protecting a page means checking if a user has logged in and has authenticated,
if so this enable him to see a view, if not the user may be redirected to a login form,
for checking this you can use the isLogged() method, 
``` 
    public function index() {
        if ($this->auth->isLogged()) {
            echo "logged";
            // "User is logged you could load a view here if you want";
        } else {
            echo "not logged";
            //user not authenticated load a login view with a form with login and password inputs
        }
    }
``` 
- When the user is not logged normally you would redirect him to a login form, 
after the user has entered his username and password, you can post these variables
and catch them on an authenticate function, here you can check if its credentials are
valid or not, using the login() method.
``` 
    public function authenticate() {
        //catch username an password inputs using the Request helper
        $username = Request::query('username');
        $password = Request::query('password');

        if ($this->auth->login($username, $password)) {
            //you can use a redirect or load a view or to index for example
            $this->index();
        } else {
            echo "not autenticated some error ocurred";
            // not authenticated you can redirect to a login view
        }
    } 
``` 

- If you want to log out use the logout() method
```
    public function logout() {

        $this->auth->logout();
        echo "logged out";
       //after logout you could redirect to a login view
    }
```

- When you want to get the current user info into an array you must use currentSessionInfo() method
```
    public function user_info(){
        print_r($this->auth->currentSessionInfo());
    }
```

- Normally when registering a new user a form should be used here is an example without it,
the register method should create a new account and send an activation email to the new user
with an activation url, in order to activate an account you must implement this activation function
and its name must be the same value from the ACTIVATION_ROUTE value on Setup.php.

```
    public function register(){
        $username = "auser";
        $password = "12345";
        $email = "somemail@email.com";
        $verifypassword = $password;
        if($this->auth->register($username, $password, $verifypassword, $email)){
            echo "register ok";
        }else{
            echo "fail";
        }
    }
```
- For activating an account recently created by the register method, the function must
catch the username and key from the activation url and then is sent to the activateAccount method.
```
public function activate(){
        $username = Request::query('username');
        $activekey = Request::query('key');
        $this->auth->activateAccount($username, $activekey);
}
```

- The directRegister method should create and activate an account without sending an activation email.

```
    public function directReg(){
        $username = "userdirect";
        $password = "12345";
        $email = "direct@email.com";
        $verifypassword = $password;
        if($this->auth->directRegister($username, $password, $verifypassword, $email)){
            echo "register ok";
        }else{
            echo "fail";
        }
    }
```


- The changePass method will change the current password with a new one 
```
    public function changePass() {
        $username = "userdirect";
        $currpassword = "12345";
        $newpass = "123456";
        $verifynewpass = "123456";

        
        if($this->auth->changePass($username, $currpassword, $newpass, $verifynewpass)){
            echo "password change ok";
        }else{
            echo "Fail";
        }
    }
```

- The changeEmail method should change the user email for a new one
```
    public function changeEmail(){
        
        $username = "userdirect";
        $email = "geomorillo@yahoo.com";
        if($this->auth->changeEmail($username, $email)){
            echo "change ok";
        }else{
            echo "Fail";
        }
    }
```
- The resetPass method should send an email with a reset key password url given the email
```
    public function requestResetPass() {
        $email = "geomorillo@yahoo.com";
        if($this->auth->resetPass($email)){
            echo "Reset key sent to $email";
        }else{
            echo "fail";
        }
    }
```

- The checkResetKey will verify if the key is valid for a given user name
- The resetPass method should reset a password given the username and the reset key and the new password

```
    public function resetPassword(){
        $username = Request::query('username');
        $resetkey = Request::query('key');
        
        if($this->auth->checkResetKey($username, $resetkey)){
            //you can do this part on another view where you redirect to a form for a new password,
            // but im inserting the new password directly
            if($this->auth->resetPass('', $username, $resetkey, '12345678', '12345678')){
                echo "Password reset ok";
            }else{
                echo "fail reset";
            }         
        }else{
            echo "Incorrect key";
        }
    }
```
- The deleteAccount should delete an account given the username and password
```
    public function deleteAccount() {
       $username = 'userdirect';
       $password = '12345678';
        if($this->auth->deleteAccount($username, $password)){
            echo "delete ok";
        }else{
            echo "delete fail";
        }
    }
```