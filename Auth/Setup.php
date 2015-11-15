<?php

namespace Helpers\Auth;

// ------------------------
// Auth Configuration :
// ------------------------
class Setup {

    public function __construct() {
        define("SITE_NAME", "TestAuth");// Name of website to appear in emails
        define("EMAIL_FROM", "geomorillo@yahoo.com");// Email FROM address for Auth emails (Activation, password reset...)
        define("MAX_ATTEMPTS",5); // INT : Max number of attempts for login before user is locked out
        define("BASE_URL","http://localhost/testauth/");// URL to Auth Class installation root WITH trailing slash
        define("ACTIVATION_FUNCTION",'activation');// this activation function is for activating an account should be implemented by you on any controller you can name it whatever you want
        define("RESET_PASSWORD_FUNCTION",'reset_password');// this reset function is for resetting a password account  an account and should be implemented  by you on any controller you can name it whatever you want
        define("SESSION_DURATION","+1 month");// Amount of time session lasts for. Only modify if you know what you are doing ! Default = +1 month
        define("SECURITY_DURATION","+5 minutes");// Amount of time to lock a user out of Auth Class after defined number of attempts.
        define("COST",10);//INT cost of BCRYPT algorithm
        define("HASH_LENGTH",22);//INT hash length of BCRYPT algorithm
        define("LOC","es"); // Language of Auth Class output : en / fr /es / de
        define('MIN_USERNAME_LENGTH',5);
        define('MAX_USERNAME_LENGTH',30);
        define('MIN_PASSWORD_LENGTH',5);
        define('MAX_PASSWORD_LENGTH',30);
        define('MAX_EMAIL_LENGTH',100);
        define('MIN_EMAIL_LENGTH',5);
        $waittime = preg_replace("/[^0-9]/", "", SECURITY_DURATION);
        define('WAIT_TIME',$waittime);// this is the same as SECURITY_DURATION but in number format
        
    }
}
