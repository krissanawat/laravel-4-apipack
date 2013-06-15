<?php namespace Apipack\Eden\Facade;

use Illuminate\Support\Facades\Facade;

class Eden extends Facade {

    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor() {
            return 'eden'; }

}