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



<!-- JS -->
<?php
Assets::js(array(
    Url::templatePath() . 'js/jquery.js',
    Url::templatePath() . 'semanticui/semantic.min.js',
    Url::templatePath() . 'js/main.js'
));

//hook for plugging in javascript
$hooks->run('js');

//hook for plugging in code into the footer
$hooks->run('footer');
?>

</body>
</html>
