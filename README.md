## Laravel 4 Apipack

Apipack is integrate api part in Eden framework to laravel.

~~~
php artisan config:publish apipack/eden
~~~

### Installation

*   Apipack[&nbsp;on Packagist](https://packagist.org/packages/teepluss/theme)
*   [Apipack&nbsp;on GitHub](https://github.com/teepluss/laravel4-theme)

To get the lastest version of Theme simply require it in your `composer.json` file.

~~~
"apipack/eden": "dev-master"
~~~

You'll then need to run `composer install` to download it and have the autoloader updated.

Once Apipack is installed you need to register the service provider with the application. Open up `app/config/app.php` and find the `providers` key.

~~~
'providers' =&gt; array(

    'Apipack\Eden\EdenServiceProvider'

);
~~~
Apipack also ships with a facade which provides the static syntax for creating collections. You can register the facade in the `aliases` key of your `app/config/app.php` file.
~~~
'aliases' => array(

    'Google' => 'Teepluss\Theme\Facades\Google',
 'Facebook' => 'Teepluss\Theme\Facades\Facebook',
 'Instagram' => 'Teepluss\Theme\Facades\Instagram',
)
~~~
### Main configuration for theme package you can add app credential in this

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
## todo
   - Amazon
   - Twitter
   - Payapl
   - Foursquare
   - Tumble

## Support or Contact

If you have some problem, Contact taqmaninw@gmail.com