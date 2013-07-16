## Laravel 4 Apipack

Apipack is integrate api part in [Eden framework](https://www.eden-php.com) to laravel.
for more information  [Eden Doc](http://www.eden-php.com/documentation/)
~~~
php artisan config:publish apipack/eden
~~~

### Installation

*   Apipack[&nbsp;on Packagist](https://packagist.org/packages/apipack/eden)
*   [Apipack&nbsp;on GitHub](https://github.com/taqmaninw/laravel-4-apipack)

To get the lastest version of Apipack simply require it in your `composer.json` file.

~~~
"apipack/eden": "dev-master"
~~~

You'll then need to run `composer install` to download it and have the autoloader updated.

Once Apipack is installed you need to register the service provider with the application. Open up `app/config/app.php` and find the `providers` key.

~~~
'providers' => array(

    'Apipack\Eden\EdenServiceProvider'

);
~~~
Apipack also ships with a facade which provides the static syntax for creating collections. You can register the facade in the `aliases` key of your `app/config/app.php` file.
~~~
'aliases' => array(

    'Google' => 'Apipack\Eden\Facade\Google',
 'Facebook' => 'Apipack\Eden\Facade\Facebook',
 'Instagram' => 'Apipack\Eden\Facade\Instagram',
)
~~~
### Main configuration for Apipack package you can add app credential in this

~~~php

return array(
    /*
     * App credential 
     *  */
    
        'Google' => array(
            'clientID' => '',
            'clientSeceret' => '',
            'redirectUrl' => '',
            'ApiKey' => ''
        ),
        'Facebook'=> array(
          'appkey'=>'',
          'appsecret'=>'',
          'redirecturl'=>''
        ),
        'Instagram'=>array(
          'clientid'=>'',
          'clientsecret'=>'',
          'redirecturl'=>''
        )
    
);

);
~~~
###

## Simple Usage
   ~~~php
$auth = Google::auth();
 
//if no code and no session
if(!isset($_GET['code']) && !isset($_SESSION['token'])) {
    //redirect to login
    $login = $auth->getLoginUrl('calendar');
    header('Location: '.$login);
    exit;
}
 
//Code is returned back from google
if(isset($_GET['code'])) {
    //save it to session
    $access = $auth->getAccess($_GET['code']);
    $_SESSION['token'] = $access['access_token'];
     
}
   ~~~
## todo
   - Amazon
   - Twitter
   - Payapl
   - Foursquare
   - Tumble

## Support or Contact

If you have some problem, Contact taqmaninw@gmail.com
