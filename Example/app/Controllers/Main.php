<?php

namespace Controllers;

use Core\View;
use Core\Controller;
use Helpers\Request as Request;

/* @author Jhobanny Morillo */

class Main extends Controller {

    private $auth;

    public function __construct() {
        parent::__construct();
        $this->auth = new \Helpers\Auth\Auth();
    }

    public function index() {
        View::renderTemplate('header');
        View::render('ajax_view');
        View::renderTemplate('footer');
    }

    public function secured() {
        if ($this->auth->isLogged()) {
            echo "all ok you are secured";
        }
    }

    public function authenticate() {
        //catch username an password inputs using the Request helper
        //"auser";"12345";
        $username = Request::post('username');
        $password = Request::post('password');
        $response = array();
        if ($this->auth->login($username, $password)) {
            if ($this->auth->errormsg) {
                // already logged in
                $response['status'] = 'already';
                $response['message'] = $this->auth->errormsg[0];
                echo json_encode($response);
            } else {
                //succesfully logged in
                $response['status'] = 'success';
                $response['message'] = $this->auth->successmsg[0];
                echo json_encode($response);
            }
        } else {
            // not authenticated
            $response['status'] = 'fail';
            $response['message'] = $this->auth->errormsg[0];
            echo json_encode($response);
        }
    }

}
