<?php

/**
 * Sample layout
 */
use Helpers\Assets;
use Helpers\Url;
use Helpers\Hooks;

//initialise hooks
$hooks = Hooks::get();
?>
<!DOCTYPE html>
<html lang="<?php echo LANGUAGE_CODE; ?>">
    <head>

        <!-- Site meta -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">

        <?php
        //hook for plugging in meta tags
        $hooks->run('meta');
        ?>
        <title><?php echo $data['title'] . ' - ' . SITETITLE; //SITETITLE defined in app/Core/Config.php  ?></title>

        <!-- CSS -->
        <?php
        Assets::css(array(
            Url::templatePath() . 'semanticui/semantic.min.css',
            Url::templatePath() . 'css/style.css'
        ));

        //hook for plugging in css
        $hooks->run('css');
        ?>

    </head>
    <body>
        <?php
//hook for running code after body tag
        $hooks->run('afterBody');
        ?>

     
