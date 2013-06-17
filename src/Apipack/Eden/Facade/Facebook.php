<?php namespace Apipack\Eden\Facade;

use Illuminate\Support\Facades\Facade;

class Facebook extends Facade {

    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor() {
            return 'facebook'; }

}
