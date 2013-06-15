<?php namespace Apipack\Eden;

use Illuminate\Support\ServiceProvider;

class EdenServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		$this->app['eden'] = $this->app->share(function($app)
        {
             
            return new Eden_Facebook;
        });
	}

   public function boot()
    {
      $this->package('vendor/package');
    }
	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array('eden');
	}

}