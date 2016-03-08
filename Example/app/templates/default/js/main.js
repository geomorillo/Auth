$(document).ready(function () {
    console.log('ok');
    $('.ui.form')
            .form({
                fields: {
                    username: {
                        identifier: 'username',
                        rules: [
                            {
                                type: 'empty',
                                prompt: 'Please enter your user name'
                            }
                        ]
                    },
                    password: {
                        identifier: 'password',
                        rules: [
                            {
                                type: 'empty',
                                prompt: 'Please enter your password'
                            },
                            {
                                type: 'length[5]',
                                prompt: 'Your password must be at least 6 characters'
                            }
                        ]
                    }
                }
            });


    $('.form').on('submit', function (event) {

        if ($('.form').form('is valid')) {
            $('.submit').addClass('disabled');
            var formData = {
                'username': $('input[name=username]').val(),
                'password': $('input[name=password]').val()
            };
            $.ajax({
                method: "POST",
                url: "login",
                data: $('.form').serialize(),
                dataType: 'json'
            }).done(function (response) {
                $('.submit').removeClass('disabled');
                switch (response.status) {
                    case 'success':
                        window.location.replace('secured/');
                        break;
                    case 'already':
                        $('.form').form('clear');
                        var path = '//' + location.host + location.pathname ;
                        var message = '<p>'+response.message+'</p>';
                        message += "<a href='"+'//' + path  +"secured'>Secure</a>&nbsp|||&nbsp<a href='"+path +"logout'>Logout</a>";
                        $('#status').html(message);
                        break;
                    case 'fail':
                        $('.form').form('clear')
                        $('#status').text(response.message);
                        break;

                }

            });

        }
        return false;

    });

});

