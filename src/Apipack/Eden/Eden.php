<?php

namespace Apipack\Eden;



if (!class_exists('Eden')) {

    class Eden {

        const DEBUG = 'DEBUG %s:';
        const INSTANCE = 0;

        private static $_instances = array();

        public static function i() {
            if (static::INSTANCE === 1) {
                return self::_getSingleton();
            }return self::_getMultiple();
        }

        public function __call($name, $args) {
            if (preg_match("/^[A-Z]/", $name)) {
                try {
                    return Eden_Route::i()->getClass($name, $args);
                } catch (Eden_Route_Error $e) {
                    
                }
            }try {
                return Eden_Route::i()->getMethod()->call($this, $name, $args);
            } catch (Eden_Route_Error $e) {
                Eden_Error::i($e->getMessage())->trigger();
            }
        }
       public function hello(){
         echo "hello eden";
       }

        public function __invoke() {
            if (func_num_args() == 0) {
                return $this;
            }$args = func_get_args();
            if (is_array($args[0])) {
                $args = $args[0];
            }$class = array_shift($args);
            if (strpos('Eden_', $class) !== 0) {
                $class = 'Eden_' . $class;
            }try {
                return Eden_Route::i()->getClass($class, $args);
            } catch (Eden_Route_Error $e) {
                Eden_Error::i($e->getMessage())->trigger();
            }
        }

        public function __toString() {
            return get_class($this);
        }

        public function callThis($method, array $args = array()) {
            Eden_Error::i()->argument(1, 'string');
            return Eden_Route::i()->getMethod($this, $method, $args);
        }

        public function debug($variable = NULL, $next = NULL) {
            $class = get_class($this);
            if (is_null($variable)) {
                Eden_Debug::i()->output(sprintf(self::DEBUG, $class))->output($this);
                return $this;
            }if ($variable === true) {
                return Eden_Debug::i()->next($this, $next);
            }if (!is_string($variable)) {
                Eden_Debug::i()->output(Eden_Error::DEBUG_NOT_STRING);
                return $this;
            }if (isset($this->$variable)) {
                Eden_Debug::i()->output(sprintf(self::DEBUG, $class . '->' . $variable))->output($this->$variable);
                return $this;
            }$private = '_' . $variable;
            if (isset($this->$private)) {
                Eden_Debug::i()->output(sprintf(self::DEBUG, $class . '->' . $private))->output($this->$private);
                return $this;
            }Eden_Debug::i()->output(sprintf(Eden_Error::DEBUG_NOT_PROPERTY, $variable, $class));
            return $this;
        }

        public function each($callback) {
            Eden_Error::i()->argument(1, 'callable');
            return Eden_Loop::i()->iterate($this, $callback);
        }

        public function routeThis($route) {
            Eden_Error::i()->argument(1, 'string');
            if (func_num_args() == 1) {
                Eden_Route::i()->getClass()->route($route, $this);
                return $this;
            }Eden_Error::i()->argument(2, 'string', 'object');
            $args = func_get_args();
            $source = array_shift($args);
            $class = array_shift($args);
            $destination = NULL;
            if (count($args)) {
                $destination = array_shift($args);
            }Eden_Route::i()->getMethod()->route($this, $source, $class, $destination);
            return $this;
        }

        public function when($isTrue, $lines = 0) {
            if ($isTrue) {
                return $this;
            }return Eden_When::i($this, $lines);
        }

        protected static function _getMultiple($class = NULL) {
            if (is_null($class) && function_exists('get_called_class')) {
                $class = get_called_class();
            }$class = Eden_Route::i()->getClass()->getRoute($class);
            return self::_getInstance($class);
        }

        protected static function _getSingleton($class = NULL) {
            if (is_null($class) && function_exists('get_called_class')) {
                $class = get_called_class();
            }$class = Eden_Route::i()->getClass()->getRoute($class);
            if (!isset(self::$_instances[$class])) {
                self::$_instances[$class] = self::_getInstance($class);
            }return self::$_instances[$class];
        }

        private static function _getInstance($class) {
            $trace = debug_backtrace();
            $args = array();
            if (isset($trace[1]['args']) && count($trace[1]['args']) > 1) {
                $args = $trace[1]['args'];
                array_shift($args);
            } else if (isset($trace[2]['args']) && count($trace[2]['args']) > 0) {
                $args = $trace[2]['args'];
            }if (count($args) === 0 || !method_exists($class, '__construct')) {
                return new $class;
            }$reflect = new ReflectionClass($class);
            try {
                return $reflect->newInstanceArgs($args);
            } catch (Reflection_Exception $e) {
                Eden_Error::i()->setMessage(Eden_Error::REFLECTION_ERROR)->addVariable($class)->addVariable('new')->trigger();
            }
        }

    }

}
/* Eden_Error */
if (!class_exists('Eden_Error')) {

    class Eden_Error extends \Exception {

        const REFLECTION_ERROR = 'Error creating Reflection Class: %s,Method: %s.';
        const INVALID_ARGUMENT = 'Argument %d in %s() was expecting %s,however %s was given.';
        const ARGUMENT = 'ARGUMENT';
        const LOGIC = 'LOGIC';
        const GENERAL = 'GENERAL';
        const CRITICAL = 'CRITICAL';
        const WARNING = 'WARNING';
        const ERROR = 'ERROR';
        const DEBUG = 'DEBUG';
        const INFORMATION = 'INFORMATION';
        const DEBUG_NOT_STRING = 'Debug was expecting a string';
        const DEBUG_NOT_PROPERTY = 'Debug: %s is not a property of %s';

        protected $_reporter = NULL;
        protected $_type = NULL;
        protected $_level = NULL;
        protected $_offset = 1;
        protected $_variables = array();
        protected $_trace = array();
        protected static $_argumentTest = true;

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

        public function __construct($message = NULL, $code = 0) {
            $this->_type = self::LOGIC;
            $this->_level = self::ERROR;
            parent::__construct($message, $code);
        }

        public function addVariable($variable) {
            $this->_variables[] = $variable;
            return $this;
        }

        public function argument($index, $types) {
            if (!self::$_argumentTest) {
                return $this;
            }$trace = debug_backtrace();
            $trace = $trace[1];
            $types = func_get_args();
            $index = array_shift($types) - 1;
            if ($index < 0) {
                $index = 0;
            }if ($index >= count($trace['args'])) {
                return $this;
            }$argument = $trace['args'][$index];
            foreach ($types as $i => $type) {
                if ($this->_isValid($type, $argument)) {
                    return $this;
                }
            }$method = $trace['function'];
            if (isset($trace['class'])) {
                $method = $trace['class'] . '->' . $method;
            }$type = $this->_getType($argument);
            $this->setMessage(self::INVALID_ARGUMENT)->addVariable($index + 1)->addVariable($method)->addVariable(implode(' or ', $types))->addVariable($type)->setTypeLogic()->setTraceOffset(1)->trigger();
        }

        public function getLevel() {
            return $this->_level;
        }

        public function getRawTrace() {
            return $this->_trace;
        }

        public function getReporter() {
            return $this->_reporter;
        }

        public function getTraceOffset() {
            return $this->_offset;
        }

        public function getType() {
            return $this->_type;
        }

        public function getVariables() {
            return $this->_variables;
        }

        public function noArgTest() {
            self::$_argumentTest = false;
            return $this;
        }

        public function setLevel($level) {
            $this->_level = $level;
            return $this;
        }

        public function setLevelDebug() {
            return $this->setLevel(self::DEBUG);
        }

        public function setLevelError() {
            return $this->setLevel(self::WARNING);
        }

        public function setLevelInformation() {
            return $this->setLevel(self::INFORMATION);
        }

        public function setLevelWarning() {
            return $this->setLevel(self::WARNING);
        }

        public function setMessage($message) {
            $this->message = $message;
            return $this;
        }

        public function setTraceOffset($offset) {
            $this->_offset = $offset;
            return $this;
        }

        public function setType($type) {
            $this->_type = $type;
            return $this;
        }

        public function setTypeArgument() {
            return $this->setType(self::ARGUMENT);
        }

        public function setTypeCritical() {
            return $this->setType(self::CRITICAL);
        }

        public function setTypeGeneral() {
            return $this->setType(self::GENERAL);
        }

        public function setTypeLogic() {
            return $this->setType(self::CRITICAL);
        }

        public function trigger() {
            $this->_trace = debug_backtrace();
            $this->_reporter = get_class($this);
            if (isset($this->_trace[$this->_offset]['class'])) {
                $this->_reporter = $this->_trace[$this->_offset]['class'];
            }if (isset($this->_trace[$this->_offset]['file'])) {
                $this->file = $this->_trace[$this->_offset]['file'];
            }if (isset($this->_trace[$this->_offset]['line'])) {
                $this->line = $this->_trace[$this->_offset]['line'];
            }if (!empty($this->_variables)) {
                $this->message = vsprintf($this->message, $this->_variables);
                $this->_variables = array();
            }throw $this;
        }

        public function vargument($method, $args, $index, $types) {
            if (!self::$_argumentTest) {
                return $this;
            }$trace = debug_backtrace();
            $trace = $trace[1];
            $types = func_get_args();
            $method = array_shift($types);
            $args = array_shift($types);
            $index = array_shift($types) - 1;
            if ($index < 0) {
                $index = 0;
            }if ($index >= count($args)) {
                return $this;
            }$argument = $args[$index];
            foreach ($types as $i => $type) {
                if ($this->_isValid($type, $argument)) {
                    return $this;
                }
            }$method = $trace['class'] . '->' . $method;
            $type = $this->_getType($argument);
            $this->setMessage(self::INVALID_ARGUMENT)->addVariable($index + 1)->addVariable($method)->addVariable(implode(' or ', $types))->addVariable($type)->setTypeLogic()->setTraceOffset(1)->trigger();
        }

        protected function _isCreditCard($value) {
            return preg_match('/^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]' . '{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-' . '5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$/', $value);
        }

        protected function _isEmail($value) {
            return preg_match('/^(?:(?:(?:[^@,"\[\]\x5c\x00-\x20\x7f-\xff\.]|\x5c(?=[@,"\[\]' . '\x5c\x00-\x20\x7f-\xff]))(?:[^@,"\[\]\x5c\x00-\x20\x7f-\xff\.]|(?<=\x5c)[@,"\[\]' . '\x5c\x00-\x20\x7f-\xff]|\x5c(?=[@,"\[\]\x5c\x00-\x20\x7f-\xff])|\.(?=[^\.])){1,62' . '}(?:[^@,"\[\]\x5c\x00-\x20\x7f-\xff\.]|(?<=\x5c)[@,"\[\]\x5c\x00-\x20\x7f-\xff])|' . '[^@,"\[\]\x5c\x00-\x20\x7f-\xff\.]{1,2})|"(?:[^"]|(?<=\x5c)"){1,62}")@(?:(?!.{64})' . '(?:[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.?|[a-zA-Z0-9]\.?)+\.(?:xn--[a-zA-Z0-9]' . '+|[a-zA-Z]{2,6})|\[(?:[0-1]?\d?\d|2[0-4]\d|25[0-5])(?:\.(?:[0-1]?\d?\d|2[0-4]\d|25' . '[0-5])){3}\])$/', $value);
        }

        protected function _isHex($value) {
            return preg_match("/^[0-9a-fA-F]{6}$/", $value);
        }

        protected function _isHtml($value) {
            return preg_match("/<\/?\w+((\s+(\w|\w[\w-]*\w)(\s*=\s*" . "(?:\".*?\"|'.*?'|[^'\">\s]+))?)+\s*|\s*)\/?>/i", $value);
        }

        protected function _isUrl($value) {
            return preg_match('/^(http|https|ftp):\/\/([A-Z0-9][A-Z0' . '-9_-]*(?:.[A-Z0-9][A-Z0-9_-]*)+):?(d+)?\/?/i', $value);
        }

        public function _alphaNum($value) {
            return preg_match('/^[a-zA-Z0-9]+$/', $value);
        }

        public function _alphaNumScore($value) {
            return preg_match('/^[a-zA-Z0-9_]+$/', $value);
        }

        public function _alphaNumHyphen($value) {
            return preg_match('/^[a-zA-Z0-9-]+$/', $value);
        }

        public function _alphaNumLine($value) {
            return preg_match('/^[a-zA-Z0-9-_]+$/', $value);
        }

        protected function _isValid($type, $data) {
            $type = $this->_getTypeName($type);
            switch ($type) {
                case 'number': return is_numeric($data);
                case 'int': return is_numeric($data) && strpos((string) $data, '.') === false;
                case 'float': return is_numeric($data) && strpos((string) $data, '.') !== false;
                case 'file': return is_string($data) && file_exists($data);
                case 'folder': return is_string($data) && is_dir($data);
                case 'email': return is_string($data) && $this->_isEmail($data);
                case 'url': return is_string($data) && $this->_isUrl($data);
                case 'html': return is_string($data) && $this->_isHtml($data);
                case 'cc': return (is_string($data) || is_int($data)) && $this->_isCreditCard($data);
                case 'hex': return is_string($data) && $this->_isHex($data);
                case 'alphanum': return is_string($data) && $this->_alphaNum($data);
                case 'alphanumscore': return is_string($data) && $this->_alphaNumScore($data);
                case 'alphanumhyphen': return is_string($data) && $this->_alphaNumHyphen($data);
                case 'alphanumline': return is_string($data) && $this->_alphaNumLine($data);
                default: break;
            }$method = 'is_' . $type;
            if (function_exists($method)) {
                return $method($data);
            }if (class_exists($type)) {
                return $data instanceof $type;
            }return true;
        }

        private function _getType($data) {
            if (is_string($data)) {
                return "'" . $data . "'";
            }if (is_numeric($data)) {
                return $data;
            }if (is_array($data)) {
                return 'Array';
            }if (is_bool($data)) {
                return $data ? 'true' : 'false';
            }if (is_object($data)) {
                return get_class($data);
            }if (is_null($data)) {
                return 'null';
            }return 'unknown';
        }

        private function _getTypeName($data) {
            if (is_string($data)) {
                return $data;
            }if (is_numeric($data)) {
                return 'numeric';
            }if (is_array($data)) {
                return 'array';
            }if (is_bool($data)) {
                return 'bool';
            }if (is_object($data)) {
                return get_class($data);
            }if (is_null($data)) {
                return 'null';
            }
        }

    }

}
/* Eden_Event */
if (!class_exists('Eden_Event')) {

    class Eden_Event extends \Eden {

        protected $_observers = array();

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function listen($event, $instance, $method = NULL, $important = false) {
            $error = Eden_Event_Error::i()->argument(1, 'string')->argument(2, 'object', 'string', 'callable')->argument(3, 'null', 'string', 'bool')->argument(4, 'bool');
            if (is_bool($method)) {
                $important = $method;
                $method = NULL;
            }$id = $this->_getId($instance, $method);
            $callable = $this->_getCallable($instance, $method);
            $observer = array($event, $id, $callable);
            if ($important) {
                array_unshift($this->_observers, $observer);
                return $this;
            }$this->_observers[] = $observer;
            return $this;
        }

        public function trigger($event = NULL) {
            Eden_Event_Error::i()->argument(1, 'string', 'null');
            if (is_null($event)) {
                $trace = debug_backtrace();
                $event = $trace[1]['function'];
            }$args = func_get_args();
            $event = array_shift($args);
            array_unshift($args, $this, $event);
            foreach ($this->_observers as $observer) {
                if ($event == $observer[0] && call_user_func_array($observer[2], $args) === false) {
                    break;
                }
            }return $this;
        }

        public function unlisten($event, $instance = NULL, $method = NULL) {
            Eden_Event_Error::i()->argument(1, 'string', 'null')->argument(2, 'object', 'string', 'null')->argument(3, 'string', 'null');
            if (is_null($event) && is_null($instance)) {
                $this->_observers = array();
                return $this;
            }$id = $this->_getId($instance, $method);
            if ($id === false) {
                return false;
            }foreach ($this->_observers as $i => $observer) {
                if (!is_null($event) && $event != $observer[0]) {
                    continue;
                }if ($id == $observer[1] && is_array($observer[2]) && $method != $observer[2][1]) {
                    continue;
                }if ($id != $observer[1]) {
                    continue;
                }unset($this->_observers[$i]);
            }return $this;
        }

        protected function _getCallable($instance, $method = NULL) {
            if (class_exists('Closure') && $instance instanceof Closure) {
                return $instance;
            }if (is_object($instance)) {
                return array($instance, $method);
            }if (is_string($instance) && is_string($method)) {
                return $instance . '::' . $method;
            }if (is_string($instance)) {
                return $instance;
            }return NULL;
        }

        protected function _getId($instance, $method = NULL) {
            if (is_object($instance)) {
                return spl_object_hash($instance);
            }if (is_string($instance) && is_string($method)) {
                return $instance . '::' . $method;
            }if (is_string($instance)) {
                return $instance;
            }return false;
        }

    }

    class Eden_Event_Error extends Eden_Error {

        const NO_METHOD = 'Instance %s was passed but,no callable method was passed in listen().';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Error_Event */
if (!class_exists('Eden_Error_Event')) {

    class Eden_Error_Event extends Eden_Event {

        const PHP = 'PHP';
        const UNKNOWN = 'UNKNOWN';
        const WARNING = 'WARNING';
        const ERROR = 'ERROR';

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function errorHandler($errno, $errstr, $errfile, $errline) {
            switch ($errno) {
                case E_NOTICE: case E_USER_NOTICE: case E_WARNING: case E_USER_WARNING: $level = self::WARNING;
                    break;
                case E_ERROR: case E_USER_ERROR: default: $level = self::ERROR;
                    break;
            }$type = self::PHP;
            $trace = debug_backtrace();
            $class = self::UNKNOWN;
            if (count($trace) > 1) {
                $class = $trace[1]['function'] . '()';
                if (isset($trace[1]['class'])) {
                    $class = $trace[1]['class'] . '->' . $class;
                }
            }$this->trigger('error', $type, $level, $class, $errfile, $errline, $errstr, $trace, 1);
            return true;
        }

        public function exceptionHandler(Exception $e) {
            $type = Eden_Error::LOGIC;
            $level = Eden_Error::ERROR;
            $offset = 1;
            $reporter = get_class($e);
            $trace = $e->getTrace();
            $message = $e->getMessage();
            if ($e instanceof Eden_Error) {
                $trace = $e->getRawTrace();
                $type = $e->getType();
                $level = $e->getLevel();
                $offset = $e->getTraceOffset();
                $reporter = $e->getReporter();
            }$this->trigger('exception', $type, $level, $reporter, $e->getFile(), $e->getLine(), $message, $trace, $offset);
        }

        public function releaseErrorHandler() {
            restore_error_handler();
            return $this;
        }

        public function releaseExceptionHandler() {
            restore_exception_handler();
            return $this;
        }

        public function setErrorHandler() {
            set_error_handler(array($this, 'errorHandler'));
            return $this;
        }

        public function setExceptionHandler() {
            set_exception_handler(array($this, 'exceptionHandler'));
            return $this;
        }

        public function setReporting($type) {
            error_reporting($type);
            return $this;
        }

    }

}
/* Eden_Route_Error */
if (!class_exists('Eden_Route_Error')) {

    class Eden_Route_Error extends Eden_Error {

        const CLASS_NOT_EXISTS = 'Invalid class call: %s->%s().Class does not exist.';
        const METHOD_NOT_EXISTS = 'Invalid class call: %s->%s().Method does not exist.';
        const STATIC_ERROR = 'Invalid class call: %s::%s().';
        const FUNCTION_ERROR = 'Invalid function run: %s().';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Route_Class */
if (!class_exists('Eden_Route_Class')) {

    class Eden_Route_Class extends \Eden {

        protected static $_instance = NULL;
        protected $_route = array();

        public static function i() {
            $class = __CLASS__;
            if (is_null(self::$_instance)) {
                self::$_instance = new $class();
            }return self::$_instance;
        }

        public function call($class) {
            Eden_Route_Error::i()->argument(1, 'string');
            $args = func_get_args();
            $class = array_shift($args);
            return $this->callArray($class, $args);
        }

        public function callArray($class, array $args = array()) {
            Eden_Route_Error::i()->argument(1, 'string');
            $route = $this->getRoute($class);
            if (is_object($route)) {
                return $route;
            }$reflect = new ReflectionClass($route);
            if (method_exists($route, 'i')) {
                $declared = $reflect->getMethod('i')->getDeclaringClass()->getName();
                return Eden_Route_Method::i()->callStatic($class, 'i', $args);
            }return $reflect->newInstanceArgs($args);
        }

        public function getRoute($route) {
            Eden_Route_Error::i()->argument(1, 'string');
            if ($this->isRoute($route)) {
                return $this->_route[strtolower($route)];
            }return $route;
        }

        public function getRoutes() {
            return $this->_route;
        }

        public function isRoute($route) {
            return isset($this->_route[strtolower($route)]);
        }

        public function release($route) {
            if ($this->isRoute($route)) {
                unset($this->_route[strtolower($route)]);
            }return $this;
        }

        public function route($route, $class) {
            Eden_Route_Error::i()->argument(1, 'string', 'object')->argument(2, 'string', 'object');
            if (is_object($route)) {
                $route = get_class($route);
            }if (is_string($class)) {
                $class = $this->getRoute($class);
            }$this->_route[strtolower($route)] = $class;
            return $this;
        }

    }

}
/* Eden_Route_Method */
if (!class_exists('Eden_Route_Method')) {

    class Eden_Route_Method extends \Eden {

        protected static $_instance = NULL;
        protected $_route = array();

        public static function i() {
            $class = __CLASS__;
            if (is_null(self::$_instance)) {
                self::$_instance = new $class();
            }return self::$_instance;
        }

        public function call($class, $method, array $args = array()) {
            Eden_Route_Error::i()->argument(1, 'string', 'object')->argument(2, 'string');
            $instance = NULL;
            if (is_object($class)) {
                $instance = $class;
                $class = get_class($class);
            }$classRoute = Eden_Route_Class::i();
            $isClassRoute = $classRoute->isRoute($class);
            $isMethodRoute = $this->isRoute($class, $method);
            list($class, $method) = $this->getRoute($class, $method);
            if (!is_object($class) && !class_exists($class)) {
                Eden_Route_Error::i()->setMessage(Eden_Route_Error::CLASS_NOT_EXISTS)->addVariable($class)->addVariable($method)->trigger();
            }if (!$isClassRoute && !$isMethodRoute && !method_exists($class, $method)) {
                Eden_Route_Error::i()->setMessage(Eden_Route_Error::METHOD_NOT_EXISTS)->addVariable($class)->addVariable($method)->trigger();
            }if ($isClassRoute || !$instance) {
                $instance = $classRoute->call($class);
            }return call_user_func_array(array(&$instance, $method), $args);
        }

        public function callStatic($class, $method, array $args = array()) {
            Eden_Route_Error::i()->argument(1, 'string', 'object')->argument(2, 'string');
            if (is_object($class)) {
                $class = get_class($class);
            }$isClassRoute = Eden_Route_Class::i()->isRoute($class);
            $isMethodRoute = $this->isRoute($class, $method);
            list($class, $method) = $this->getRoute($class, $method);
            if (!is_object($class) && !class_exists($class)) {
                Eden_Route_Error::i()->setMessage(Eden_Route_Error::CLASS_NOT_EXISTS)->addVariable($class)->addVariable($method)->trigger();
            }if (!$isClassRoute && !$isMethodRoute && !method_exists($class, $method)) {
                Eden_Route_Error::i()->setMessage(Eden_Route_Error::METHOD_NOT_EXISTS)->addVariable($class)->addVariable($method)->trigger();
            }if (is_object($class)) {
                $class = get_class($class);
            }return call_user_func_array($class . '::' . $method, $args);
        }

        public function getRoute($class, $method) {
            Eden_Route_Error::i()->argument(1, 'string')->argument(2, 'string');
            if ($this->isRoute(NULL, $method)) {
                return $this->_route[NULL][strtolower($method)];
            }$class = Eden_Route_Class::i()->getRoute($class);
            if ($this->isRoute($class, $method)) {
                return $this->_route[strtolower($class)][strtolower($method)];
            }return array($class, $method);
        }

        public function getRoutes() {
            return $this->_route;
        }

        public function isRoute($class, $method) {
            if (is_string($class)) {
                $class = strtolower($class);
            }return isset($this->_route[$class][strtolower($method)]);
        }

        public function release($class, $method) {
            if ($this->isRoute($class, $method)) {
                unset($this->_route[strtolower($class)][strtolower($method)]);
            }return $this;
        }

        public function route($source, $alias, $class, $method = NULL) {
            Eden_Route_Error::i()->argument(1, 'string', 'object', 'null')->argument(2, 'string')->argument(3, 'string', 'object')->argument(4, 'string');
            if (is_object($source)) {
                $source = get_class($source);
            }if (!is_string($method)) {
                $method = $alias;
            }$route = Eden_Route_Class::i();
            if (!is_null($source)) {
                $source = $route->getRoute($source);
                $source = strtolower($source);
            }if (is_string($class)) {
                $class = $route->getRoute($class);
            }$this->_route[$source][strtolower($alias)] = array($class, $method);
            return $this;
        }

    }

}
/* Eden_Route_Function */
if (!class_exists('Eden_Route_Function')) {

    class Eden_Route_Function extends \Eden {

        protected static $_instance = NULL;
        protected $_route = array();

        public static function i() {
            $class = __CLASS__;
            if (is_null(self::$_instance)) {
                self::$_instance = new $class();
            }return self::$_instance;
        }

        public function call($function) {
            Eden_Route_Error::i()->argument(1, 'string');
            $args = func_get_args();
            $function = array_shift($args);
            return $this->callArray($function, $args);
        }

        public function callArray($function, array $args = array()) {
            Eden_Route_Error::i()->argument(1, 'string');
            $function = $this->getRoute($function);
            return call_user_func_array($function, $args);
        }

        public function getRoute($route) {
            Eden_Route_Error::i()->argument(1, 'string');
            if ($this->isRoute($route)) {
                return $this->_route[strtolower($route)];
            }return $route;
        }

        public function getRoutes() {
            return $this->_route;
        }

        public function isRoute($route) {
            return isset($this->_route[strtolower($route)]);
        }

        public function release($route) {
            if ($this->isRoute($route)) {
                unset($this->_route[strtolower($route)]);
            }return $this;
        }

        public function route($route, $function) {
            Eden_Route_Error::i()->argument(1, 'string')->argument(2, 'string');
            $function = $this->getRoute($function);
            $this->_route[strtolower($route)] = $function;
            return $this;
        }

    }

}
/* Eden_Route */
if (!class_exists('Eden_Route')) {

    class Eden_Route extends \Eden {

        protected static $_instance = NULL;

        public static function i() {
            $class = __CLASS__;
            if (is_null(self::$_instance)) {
                self::$_instance = new $class();
            }return self::$_instance;
        }

        public function getClass($class = NULL, array $args = array()) {
            $route = Eden_Route_Class::i();
            if (is_null($class)) {
                return $route;
            }return $route->callArray($class, $args);
        }

        public function getFunction($function = NULL, array $args = array()) {
            $route = Eden_Route_Function::i();
            if (is_null($function)) {
                return $route;
            }return $route->callArray($function, $args);
        }

        public function getMethod($class = NULL, $method = NULL, array $args = array()) {
            $route = Eden_Route_Method::i();
            if (is_null($class) || is_null($method)) {
                return $route;
            }return $route->call($class, $method, $args);
        }

    }

}
/* Eden_When */
if (!class_exists('Eden_When')) {

    class Eden_When extends \Eden implements \ArrayAccess, \Iterator {

        protected $_scope = NULL;
        protected $_increment = 1;
        protected $_lines = 0;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($scope, $lines = 0) {
            $this->_scope = $scope;
            $this->_lines = $lines;
        }

        public function __call($name, $args) {
            if ($this->_lines > 0 && $this->_increment == $this->_lines) {
                return $this->_scope;
            }$this->_increment++;
            return $this;
        }

        public function current() {
            return $this->_scope->current();
        }

        public function key() {
            return $this->_scope->key();
        }

        public function next() {
            $this->_scope->next();
        }

        public function offsetExists($offset) {
            return $this->_scope->offsetExists($offset);
        }

        public function offsetGet($offset) {
            return $this->_scope->offsetGet($offset);
        }

        public function offsetSet($offset, $value) {
            
        }

        public function offsetUnset($offset) {
            
        }

        public function rewind() {
            $this->_scope->rewind();
        }

        public function valid() {
            return $this->_scope->valid();
        }

    }

}
/* Eden_Debug */
if (!class_exists('Eden_Debug')) {

    class Eden_Debug extends \Eden {

        protected $_scope = NULL;
        protected $_name = NULL;

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function __call($name, $args) {
            if (is_null($this->_scope)) {
                return parent::__call($name, $args);
            }$results = $this->_getResults($name, $args);
            $name = $this->_name;
            $scope = $this->_scope;
            $this->_name = NULL;
            $this->_scope = NULL;
            if ($name) {
                $scope->debug($name);
                return $results;
            }$class = get_class($scope);
            $this->output(sprintf(self::DEBUG, $class . '->' . $name))->output($results);
            return $results;
        }

        public function next($scope, $name = NULL) {
            Eden_Error::i()->argument(1, 'object')->argument(2, 'string', 'null');
            $this->_scope = $scope;
            $this->_name = $name;
            return $this;
        }

        public function output($variable) {
            if ($variable === true) {
                $variable = '*TRUE*';
            } else if ($variable === false) {
                $variable = '*FALSE*';
            } else if (is_null($variable)) {
                $variable = '*NULL*';
            }echo '<pre>' . print_r($variable, true) . '</pre>';
            return $this;
        }

        protected function _getResults($name, $args) {
            if (method_exists($this->_scope, $name)) {
                return call_user_func_array(array($this->_scope, $name), $args);
            }return $this->_scope->__call($name, $args);
        }

    }

}
/* Eden_Loop */
if (!class_exists('Eden_Loop')) {

    class Eden_Loop extends \Eden {

        protected $_scope = NULL;
        protected $_callback = NULL;

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function __call($name, $args) {
            if (is_null($this->_scope)) {
                return parent::__call($name, $args);
            }$results = $this->_getResults($name, $args);
            $loopable = is_scalar($results) ? array($results) : $results;
            foreach ($loopable as $key => $value) {
                if (call_user_func($this->_callback, $key, $value) === false) {
                    break;
                }
            }return $results;
        }

        public function iterate($scope, $callback) {
            Eden_Error::i()->argument(1, 'object')->argument(2, 'callable');
            $this->_scope = $scope;
            $this->_callback = $callback;
            return $this;
        }

        protected function _getResults($name, $args) {
            if (method_exists($this->_scope, $name)) {
                return call_user_func_array(array($this->_scope, $name), $args);
            }return $this->_scope->__call($name, $args);
        }

    }

}
/* Eden_Loader */
if (!class_exists('Eden_Loader')) {

    class Eden_Loader extends \Eden {

        protected $_root = array();

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function __construct($eden = true) {
            if ($eden) {
                $this->addRoot(realpath(dirname(__FILE__) . '/..'));
            }
        }

        public function __call($name, $args) {
            if (preg_match("/^[A-Z]/", $name)) {
                $this->load($name);
            }return parent::__call($name, $args);
        }

        public function addRoot($path) {
            array_unshift($this->_root, $path);
            return $this;
        }

        public function handler($class) {
            if (!is_string($class)) {
                return false;
            }$path = str_replace(array('_', '\\'), '/', $class);
            $path = '/' . strtolower($path);
            $path = str_replace('//', '/', $path);
            foreach ($this->_root as $root) {
                $file = $root . $path . '.php';
                if (file_exists($file) && require_once($file)) {
                    return true;
                }
            }return false;
        }

        public function load($class) {
            if (!class_exists($class)) {
                $this->handler($class);
            }return $this;
        }

    }

}
/* Eden_Type */
if (!class_exists('Eden_Type')) {

    class Eden_Type extends \Eden {

        public static function i($type = NULL) {
            if (func_num_args() > 1) {
                $type = func_get_args();
            }if (is_array($type)) {
                return Eden_Type_Array::i($type);
            }if (is_string($type)) {
                return Eden_Type_String::i($type);
            }return self::_getSingleton(__CLASS__);
        }

        public function getArray($array) {
            $args = func_get_args();
            if (count($args) > 1 || !is_array($array)) {
                $array = $args;
            }return Eden_Type_Array::i($array);
        }

        public function getString($string) {
            return Eden_Type_String::i($string);
        }

    }

}
/* Eden_Type_Abstract */
if (!class_exists('Eden_Type_Abstract')) {

    abstract class Eden_Type_Abstract extends \Eden {

        const PRE = 'pre';
        const POST = 'post';
        const REFERENCE = 'reference';

        protected $_data = NULL;
        protected $_original = NULL;

        public function __call($name, $args) {
            $type = $this->_getMethodType($name);
            if (!$type) {
                try {
                    return parent::__call($name, $args);
                } catch (Eden_Error $e) {
                    Eden_Type_Error::i($e->getMessage())->trigger();
                }
            }switch ($type) {
                case self::PRE: array_unshift($args, $this->_data);
                    break;
                case self::POST: array_push($args, $this->_data);
                    break;
                case self::REFERENCE: call_user_func_array($name, array_merge(array(&$this->_data), $args));
                    return $this;
            }$result = call_user_func_array($name, $args);
            if (is_string($result)) {
                if ($this instanceof Eden_Type_String) {
                    $this->_data = $result;
                    return $this;
                }return Eden_Type_String::i($result);
            }if (is_array($result)) {
                if ($this instanceof Eden_Type_Array) {
                    $this->_data = $result;
                    return $this;
                }return Eden_Type_Array::i($result);
            }return $result;
        }

        public function __construct($data) {
            $this->_original = $this->_data = $data;
        }

        public function get($modified = true) {
            Eden_Type_Error::i()->argument(1, 'bool');
            return $modified ? $this->_data : $this->_original;
        }

        public function revert() {
            $this->_data = $this->_original;
            return $this;
        }

        public function set($value) {
            $this->_data = $value;
            return $this;
        }

        abstract protected function _getMethodType(&$name);
    }

}
/* Eden_Type_Error */
if (!class_exists('Eden_Type_Error')) {

    class Eden_Type_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Type_Array */
if (!class_exists('Eden_Type_Array')) {

    class Eden_Type_Array extends Eden_Type_Abstract implements \ArrayAccess, \Iterator, \Serializable, \Countable {

        protected $_data = array();
        protected $_original = array();
        protected static $_methods = array('array_change_key_case' => self::PRE, 'array_chunk' => self::PRE, 'array_combine' => self::PRE, 'array_count_datas' => self::PRE, 'array_diff_assoc' => self::PRE, 'array_diff_key' => self::PRE, 'array_diff_uassoc' => self::PRE, 'array_diff_ukey' => self::PRE, 'array_diff' => self::PRE, 'array_fill_keys' => self::PRE, 'array_filter' => self::PRE, 'array_flip' => self::PRE, 'array_intersect_assoc' => self::PRE, 'array_intersect_key' => self::PRE, 'array_intersect_uassoc' => self::PRE, 'array_intersect_ukey' => self::PRE, 'array_intersect' => self::PRE, 'array_keys' => self::PRE, 'array_merge_recursive' => self::PRE, 'array_merge' => self::PRE, 'array_pad' => self::PRE, 'array_reverse' => self::PRE, 'array_shift' => self::PRE, 'array_slice' => self::PRE, 'array_splice' => self::PRE, 'array_sum' => self::PRE, 'array_udiff_assoc' => self::PRE, 'array_udiff_uassoc' => self::PRE, 'array_udiff' => self::PRE, 'array_uintersect_assoc' => self::PRE, 'array_uintersect_uassoc' => self::PRE, 'array_uintersect' => self::PRE, 'array_unique' => self::PRE, 'array_datas' => self::PRE, 'count' => self::PRE, 'current' => self::PRE, 'each' => self::PRE, 'end' => self::PRE, 'extract' => self::PRE, 'key' => self::PRE, 'next' => self::PRE, 'prev' => self::PRE, 'sizeof' => self::PRE, 'array_fill' => self::POST, 'array_map' => self::POST, 'array_search' => self::POST, 'compact' => self::POST, 'implode' => self::POST, 'in_array' => self::POST, 'array_unshift' => self::REFERENCE, 'array_walk_recursive' => self::REFERENCE, 'array_walk' => self::REFERENCE, 'arsort' => self::REFERENCE, 'asort' => self::REFERENCE, 'krsort' => self::REFERENCE, 'ksort' => self::REFERENCE, 'natcasesort' => self::REFERENCE, 'natsort' => self::REFERENCE, 'reset' => self::REFERENCE, 'rsort' => self::REFERENCE, 'shuffle' => self::REFERENCE, 'sort' => self::REFERENCE, 'uasort' => self::REFERENCE, 'uksort' => self::REFERENCE, 'usort' => self::REFERENCE, 'array_push' => self::REFERENCE);

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __call($name, $args) {
            if (strpos($name, 'get') === 0) {
                $separator = '_';
                if (isset($args[0]) && is_scalar($args[0])) {
                    $separator = (string) $args[0];
                }$key = preg_replace("/([A-Z0-9])/", $separator . "$1", $name);
                $key = strtolower(substr($key, 3 + strlen($separator)));
                if (isset($this->_data[$key])) {
                    return $this->_data[$key];
                }return NULL;
            } else if (strpos($name, 'set') === 0) {
                $separator = '_';
                if (isset($args[1]) && is_scalar($args[1])) {
                    $separator = (string) $args[1];
                }$key = preg_replace("/([A-Z0-9])/", $separator . "$1", $name);
                $key = strtolower(substr($key, 3 + strlen($separator)));
                $this->__set($key, isset($args[0]) ? $args[0] : NULL);
                return $this;
            }try {
                return parent::__call($name, $args);
            } catch (Eden_Error $e) {
                Eden_Type_Error::i($e->getMessage())->trigger();
            }
        }

        public function __construct($data = array()) {
            if (func_num_args() > 1 || !is_array($data)) {
                $data = func_get_args();
            }parent::__construct($data);
        }

        public function __set($name, $value) {
            $this->_data[$name] = $value;
        }

        public function __toString() {
            return json_encode($this->get());
        }

        public function copy($source, $destination) {
            $this->_data[$destination] = $this->_data[$source];
            return $this;
        }

        public function count() {
            return count($this->_data);
        }

        public function cut($key) {
            Eden_Type_Error::i()->argument(1, 'scalar');
            if (!isset($this->_data[$key])) {
                return $this;
            }unset($this->_data[$key]);
            $this->_data = array_values($this->_data);
            return $this;
        }

        public function current() {
            return current($this->_data);
        }

        public function each($callback) {
            Eden_Error::i()->argument(1, 'callable');
            foreach ($this->_data as $key => $value) {
                call_user_func($callback, $key, $value);
            }return $this;
        }

        public function isEmpty() {
            return empty($this->_data);
        }

        public function key() {
            return key($this->_data);
        }

        public function next() {
            next($this->_data);
        }

        public function offsetExists($offset) {
            return isset($this->_data[$offset]);
        }

        public function offsetGet($offset) {
            return isset($this->_data[$offset]) ? $this->_data[$offset] : NULL;
        }

        public function offsetSet($offset, $value) {
            if (is_null($offset)) {
                $this->_data[] = $value;
            } else {
                $this->_data[$offset] = $value;
            }
        }

        public function offsetUnset($offset) {
            unset($this->_data[$offset]);
        }

        public function paste($after, $value, $key = NULL) {
            Eden_Type_Error::i()->argument(1, 'scalar')->argument(3, 'scalar', 'null');
            $list = array();
            foreach ($this->_data as $i => $val) {
                $list[$i] = $val;
                if ($after != $i) {
                    continue;
                }if (!is_null($key)) {
                    $list[$key] = $value;
                    continue;
                }$list[] = $arrayValue;
            }if (is_null($key)) {
                $list = array_values($list);
            }$this->_data = $list;
            return $this;
        }

        public function rewind() {
            reset($this->_data);
        }

        public function serialize() {
            return json_encode($this->_data);
        }

        public function set($value) {
            Eden_Type_Error::i()->argument(1, 'array');
            $this->_data = $value;
            return $this;
        }

        public function unserialize($data) {
            $this->_data = json_decode($data, true);
            return $this;
        }

        public function valid() {
            return isset($this->_data[$this->key()]);
        }

        protected function _getMethodType(&$name) {
            if (isset(self::$_methods[$name])) {
                return self::$_methods[$name];
            }if (isset(self::$_methods['array_' . $name])) {
                $name = 'array_' . $name;
                return self::$_methods[$name];
            }$uncamel = strtolower(preg_replace("/([A-Z])/", "_$1", $name));
            if (isset(self::$_methods[$uncamel])) {
                $name = $uncamel;
                return self::$_methods[$name];
            }if (isset(self::$_methods['array_' . $uncamel])) {
                $name = 'array_' . $uncamel;
                return self::$_methods[$name];
            }return false;
        }

    }

}
/* Eden_Type_String */
if (!class_exists('Eden_Type_String')) {

    class Eden_Type_String extends Eden_Type_Abstract {

        protected static $_methods = array('addslashes' => self::PRE, 'bin2hex' => self::PRE, 'chunk_split' => self::PRE, 'convert_uudecode' => self::PRE, 'convert_uuencode' => self::PRE, 'crypt' => self::PRE, 'html_entity_decode' => self::PRE, 'htmlentities' => self::PRE, 'htmlspecialchars_decode' => self::PRE, 'htmlspecialchars' => self::PRE, 'lcfirst' => self::PRE, 'ltrim' => self::PRE, 'md5' => self::PRE, 'nl2br' => self::PRE, 'quoted_printable_decode' => self::PRE, 'quoted_printable_encode' => self::PRE, 'quotemeta' => self::PRE, 'rtrim' => self::PRE, 'sha1' => self::PRE, 'sprintf' => self::PRE, 'str_pad' => self::PRE, 'str_repeat' => self::PRE, 'str_rot13' => self::PRE, 'str_shuffle' => self::PRE, 'strip_tags' => self::PRE, 'stripcslashes' => self::PRE, 'stripslashes' => self::PRE, 'strpbrk' => self::PRE, 'stristr' => self::PRE, 'strrev' => self::PRE, 'strstr' => self::PRE, 'strtok' => self::PRE, 'strtolower' => self::PRE, 'strtoupper' => self::PRE, 'strtr' => self::PRE, 'substr_replace' => self::PRE, 'substr' => self::PRE, 'trim' => self::PRE, 'ucfirst' => self::PRE, 'ucwords' => self::PRE, 'vsprintf' => self::PRE, 'wordwrap' => self::PRE, 'count_chars' => self::PRE, 'hex2bin' => self::PRE, 'strlen' => self::PRE, 'strpos' => self::PRE, 'substr_compare' => self::PRE, 'substr_count' => self::PRE, 'str_ireplace' => self::POST, 'str_replace' => self::POST, 'preg_replace' => self::POST, 'explode' => self::POST);

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($data) {
            Eden_Type_Error::i()->argument(1, 'scalar');
            $data = (string) $data;
            parent::__construct($data);
        }

        public function __toString() {
            return $this->_data;
        }

        public function camelize($prefix = '-') {
            Eden_Type_Error::i()->argument(1, 'string');
            $this->_data = str_replace($prefix, ' ', $this->_data);
            $this->_data = str_replace(' ', '', ucwords($this->_data));
            $this->_data = strtolower(substr($name, 0, 1)) . substr($name, 1);
            return $this;
        }

        public function dasherize() {
            $this->_data = preg_replace("/[^a-zA-Z0-9_-\s]/i", '', $this->_data);
            $this->_data = str_replace(' ', '-', trim($this->_data));
            $this->_data = preg_replace("/-+/i", '-', $this->_data);
            $this->_data = strtolower($this->_data);
            return $this;
        }

        public function titlize($prefix = '-') {
            Eden_Type_Error::i()->argument(1, 'string');
            $this->_data = ucwords(str_replace($prefix, ' ', $this->_data));
            return $this;
        }

        public function uncamelize($prefix = '-') {
            Eden_Type_Error::i()->argument(1, 'string');
            $this->_data = strtolower(preg_replace("/([A-Z])/", $prefix . "$1", $this->_data));
            return $this;
        }

        public function summarize($words) {
            Eden_Type_Error::i()->argument(1, 'int');
            $this->_data = explode(' ', strip_tags($this->_data), $words);
            array_pop($this->_data);
            $this->_data = implode(' ', $this->_data);
            return $this;
        }

        protected function _getMethodType(&$name) {
            if (isset(self::$_methods[$name])) {
                return self::$_methods[$name];
            }if (isset(self::$_methods['str_' . $name])) {
                $name = 'str_' . $name;
                return self::$_methods[$name];
            }$uncamel = strtolower(preg_replace("/([A-Z])/", "_$1", $name));
            if (isset(self::$_methods[$uncamel])) {
                $name = $uncamel;
                return self::$_methods[$name];
            }if (isset(self::$_methods['str_' . $uncamel])) {
                $name = 'str_' . $uncamel;
                return self::$_methods[$name];
            }return false;
        }

    }

}
/* Eden_Collection */
if (!class_exists('Eden_Collection')) {

    class Eden_Collection extends \Eden implements \ArrayAccess, \Iterator, \Serializable, \Countable {

        const FIRST = 'first';
        const LAST = 'last';
        const MODEL = 'Eden_Model';

        protected $_list = array();
        protected $_model = self::MODEL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __call($name, $args) {
            if (strpos($name, 'get') === 0) {
                $value = isset($args[0]) ? $args[0] : NULL;
                $list = array();
                foreach ($this->_list as $i => $row) {
                    $list[] = $row->$name(isset($args[0]) ? $args[0] : NULL);
                }return $list;
            } else if (strpos($name, 'set') === 0) {
                $value = isset($args[0]) ? $args[0] : NULL;
                $separator = isset($args[1]) ? $args[1] : NULL;
                foreach ($this->_list as $i => $row) {
                    $row->$name($value, $separator);
                }return $this;
            }$found = false;
            foreach ($this->_list as $i => $row) {
                if (!method_exists($row, $name)) {
                    continue;
                }$found = true;
                $row->callThis($name, $args);
            }if ($found) {
                return $this;
            }try {
                return parent::__call($name, $args);
            } catch (Eden_Error $e) {
                Eden_Collection_Error::i($e->getMessage())->trigger();
            }
        }

        public function __construct(array $data = array()) {
            $this->set($data);
        }

        public function __set($name, $value) {
            foreach ($this->_list as $i => $row) {
                $row[$name] = $value;
            }return $this;
        }

        public function __toString() {
            return json_encode($this->get());
        }

        public function add($row = array()) {
            Eden_Collection_Error::i()->argument(1, 'array', $this->_model);
            if (is_array($row)) {
                $model = $this->_model;
                $row = $this->$model($row);
            }$this->_list[] = $row;
            return $this;
        }

        public function count() {
            return count($this->_list);
        }

        public function cut($index = self::LAST) {
            Eden_Collection_Error::i()->argument(1, 'string', 'int');
            if ($index == self::FIRST) {
                $index = 0;
            } else if ($index == self::LAST) {
                $index = count($this->_list) - 1;
            }if (isset($this->_list[$index])) {
                unset($this->_list[$index]);
            }$this->_list = array_values($this->_list);
            return $this;
        }

        public function each($callback) {
            Eden_Error::i()->argument(1, 'callable');
            foreach ($this->_list as $key => $value) {
                call_user_func($callback, $key, $value);
            }return $this;
        }

        public function current() {
            return current($this->_list);
        }

        public function get($modified = true) {
            Eden_Collection_Error::i()->argument(1, 'bool');
            $array = array();
            foreach ($this->_list as $i => $row) {
                $array[$i] = $row->get($modified);
            }return $array;
        }

        public function key() {
            return key($this->_list);
        }

        public function next() {
            next($this->_list);
        }

        public function offsetExists($offset) {
            return isset($this->_list[$offset]);
        }

        public function offsetGet($offset) {
            return isset($this->_list[$offset]) ? $this->_list[$offset] : NULL;
        }

        public function offsetSet($offset, $value) {
            Eden_Collection_Error::i()->argument(2, 'array', $this->_model);
            if (is_array($value)) {
                $model = $this->_model;
                $value = $this->$model($value);
            }if (is_null($offset)) {
                $this->_list[] = $value;
            } else {
                $this->_list[$offset] = $value;
            }
        }

        public function offsetUnset($offset) {
            $this->_list = Eden_Model::i($this->_list)->cut($offset)->get();
        }

        public function rewind() {
            reset($this->_list);
        }

        public function serialize() {
            return $this->__toString();
        }

        public function set(array $data = array()) {
            foreach ($data as $row) {
                $this->add($row);
            }return $this;
        }

        public function setModel($model) {
            $error = Eden_Collection_Error::i()->argument(1, 'string');
            if (!is_subclass_of($model, 'Eden_Model')) {
                $error->setMessage(Eden_Collection_Error::NOT_SUB_MODEL)->addVariable($model)->trigger();
            }$this->_model = $model;
            return $this;
        }

        public function unserialize($data) {
            $this->_list = json_decode($data, true);
            return $this;
        }

        public function valid() {
            return isset($this->_list[key($this->_list)]);
        }

    }

    class Eden_Collection_Error extends Eden_Error {

        const NOT_COLLECTION = 'The data passed into __construct is not a collection.';
        const NOT_SUB_MODEL = 'Class %s is not a child of Eden_Model';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Curl */
if (!class_exists('Eden_Curl')) {

    class Eden_Curl extends \Eden implements \ArrayAccess {

        const PUT = 'PUT';
        const DELETE = 'DELETE';
        const GET = 'GET';
        const POST = 'POST';

        protected $_options = array();
        protected $_meta = array();
        protected $_query = array();
        protected $_headers = array();
        protected static $_setBoolKeys = array('AutoReferer' => CURLOPT_AUTOREFERER, 'BinaryTransfer' => CURLOPT_BINARYTRANSFER, 'CookieSession' => CURLOPT_COOKIESESSION, 'CrlF' => CURLOPT_CRLF, 'DnsUseGlobalCache' => CURLOPT_DNS_USE_GLOBAL_CACHE, 'FailOnError' => CURLOPT_FAILONERROR, 'FileTime' => CURLOPT_FILETIME, 'FollowLocation' => CURLOPT_FOLLOWLOCATION, 'ForbidReuse' => CURLOPT_FORBID_REUSE, 'FreshConnect' => CURLOPT_FRESH_CONNECT, 'FtpUseEprt' => CURLOPT_FTP_USE_EPRT, 'FtpUseEpsv' => CURLOPT_FTP_USE_EPSV, 'FtpAppend' => CURLOPT_FTPAPPEND, 'FtpListOnly' => CURLOPT_FTPLISTONLY, 'Header' => CURLOPT_HEADER, 'HeaderOut' => CURLINFO_HEADER_OUT, 'HttpGet' => CURLOPT_HTTPGET, 'HttpProxyTunnel' => CURLOPT_HTTPPROXYTUNNEL, 'Netrc' => CURLOPT_NETRC, 'Nobody' => CURLOPT_NOBODY, 'NoProgress' => CURLOPT_NOPROGRESS, 'NoSignal' => CURLOPT_NOSIGNAL, 'Post' => CURLOPT_POST, 'Put' => CURLOPT_PUT, 'ReturnTransfer' => CURLOPT_RETURNTRANSFER, 'SslVerifyPeer' => CURLOPT_SSL_VERIFYPEER, 'TransferText' => CURLOPT_TRANSFERTEXT, 'UnrestrictedAuth' => CURLOPT_UNRESTRICTED_AUTH, 'Upload' => CURLOPT_UPLOAD, 'Verbose' => CURLOPT_VERBOSE);
        protected static $_setIntegerKeys = array('BufferSize' => CURLOPT_BUFFERSIZE, 'ClosePolicy' => CURLOPT_CLOSEPOLICY, 'ConnectTimeout' => CURLOPT_CONNECTTIMEOUT, 'ConnectTimeoutMs' => CURLOPT_CONNECTTIMEOUT_MS, 'DnsCacheTimeout' => CURLOPT_DNS_CACHE_TIMEOUT, 'FtpSslAuth' => CURLOPT_FTPSSLAUTH, 'HttpVersion' => CURLOPT_HTTP_VERSION, 'HttpAuth' => CURLOPT_HTTPAUTH, 'InFileSize' => CURLOPT_INFILESIZE, 'LowSpeedLimit' => CURLOPT_LOW_SPEED_LIMIT, 'LowSpeedTime' => CURLOPT_LOW_SPEED_TIME, 'MaxConnects' => CURLOPT_MAXCONNECTS, 'MaxRedirs' => CURLOPT_MAXREDIRS, 'Port' => CURLOPT_PORT, 'ProxyAuth' => CURLOPT_PROXYAUTH, 'ProxyPort' => CURLOPT_PROXYPORT, 'ProxyType' => CURLOPT_PROXYTYPE, 'ResumeFrom' => CURLOPT_RESUME_FROM, 'SslVerifyHost' => CURLOPT_SSL_VERIFYHOST, 'SslVersion' => CURLOPT_SSLVERSION, 'TimeCondition' => CURLOPT_TIMECONDITION, 'Timeout' => CURLOPT_TIMEOUT, 'TimeoutMs' => CURLOPT_TIMEOUT_MS, 'TimeValue' => CURLOPT_TIMEVALUE);
        protected static $_setStringKeys = array('CaInfo' => CURLOPT_CAINFO, 'CaPath' => CURLOPT_CAPATH, 'Cookie' => CURLOPT_COOKIE, 'CookieFile' => CURLOPT_COOKIEFILE, 'CookieJar' => CURLOPT_COOKIEJAR, 'CustomRequest' => CURLOPT_CUSTOMREQUEST, 'EgdSocket' => CURLOPT_EGDSOCKET, 'Encoding' => CURLOPT_ENCODING, 'FtpPort' => CURLOPT_FTPPORT, 'Interface' => CURLOPT_INTERFACE, 'Krb4Level' => CURLOPT_KRB4LEVEL, 'PostFields' => CURLOPT_POSTFIELDS, 'Proxy' => CURLOPT_PROXY, 'ProxyUserPwd' => CURLOPT_PROXYUSERPWD, 'RandomFile' => CURLOPT_RANDOM_FILE, 'Range' => CURLOPT_RANGE, 'Referer' => CURLOPT_REFERER, 'SslCipherList' => CURLOPT_SSL_CIPHER_LIST, 'SslCert' => CURLOPT_SSLCERT, 'SslCertPassword' => CURLOPT_SSLCERTPASSWD, 'SslCertType' => CURLOPT_SSLCERTTYPE, 'SslEngine' => CURLOPT_SSLENGINE, 'SslEngineDefault' => CURLOPT_SSLENGINE_DEFAULT, 'Sslkey' => CURLOPT_SSLKEY, 'SslKeyPasswd' => CURLOPT_SSLKEYPASSWD, 'SslKeyType' => CURLOPT_SSLKEYTYPE, 'Url' => CURLOPT_URL, 'UserAgent' => CURLOPT_USERAGENT, 'UserPwd' => CURLOPT_USERPWD);
        protected static $_setArrayKeys = array('Http200Aliases' => CURLOPT_HTTP200ALIASES, 'HttpHeader' => CURLOPT_HTTPHEADER, 'PostQuote' => CURLOPT_POSTQUOTE, 'Quote' => CURLOPT_QUOTE);
        protected static $_setFileKeys = array('File' => CURLOPT_FILE, 'InFile' => CURLOPT_INFILE, 'StdErr' => CURLOPT_STDERR, 'WriteHeader' => CURLOPT_WRITEHEADER);
        protected static $_setCallbackKeys = array('HeaderFunction' => CURLOPT_HEADERFUNCTION, 'ReadFunction' => CURLOPT_READFUNCTION, 'WriteFunction' => CURLOPT_WRITEFUNCTION);

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __call($name, $args) {
            if (strpos($name, 'set') === 0) {
                $method = substr($name, 3);
                if (isset(self::$_setBoolKeys[$method])) {
                    Eden_Curl_Error::i()->vargument($name, $args, 1, 'bool');
                    $key = self::$_setBoolKeys[$method];
                    $this->_options[$key] = $args[0];
                    return $this;
                }if (isset(self::$_setIntegerKeys[$method])) {
                    Eden_Curl_Error::i()->vargument($name, $args, 1, 'int');
                    $key = self::$_setIntegerKeys[$method];
                    $this->_options[$key] = $args[0];
                    return $this;
                }if (isset(self::$_setStringKeys[$method])) {
                    Eden_Curl_Error::i()->vargument($name, $args, 1, 'string');
                    $key = self::$_setStringKeys[$method];
                    $this->_options[$key] = $args[0];
                    return $this;
                }if (isset(self::$_setArrayKeys[$method])) {
                    Eden_Curl_Error::i()->vargument($name, $args, 1, 'array');
                    $key = self::$_setArrayKeys[$method];
                    $this->_options[$key] = $args[0];
                    return $this;
                }if (isset(self::$_setFileKeys[$method])) {
                    $key = self::$_setFileKeys[$method];
                    $this->_options[$key] = $args[0];
                    return $this;
                }if (isset(self::$_setCallbackKeys[$method])) {
                    Eden_Curl_Error::i()->vargument($name, $args, 1, 'array', 'string');
                    $key = self::$_setCallbackKeys[$method];
                    $this->_options[$key] = $args[0];
                    return $this;
                }
            }parent::__call($name, $args);
        }

        public function getDomDocumentResponse() {
            $this->_meta['response'] = $this->getResponse();
            $xml = new DOMDocument();
            $xml->loadXML($this->_meta['response']);
            return $xml;
        }

        public function getJsonResponse($assoc = true) {
            $this->_meta['response'] = $this->getResponse();
            Eden_Curl_Error::i()->argument(1, 'bool');
            return json_decode($this->_meta['response'], $assoc);
        }

        public function getMeta($key = NULL) {
            Eden_Curl_Error::i()->argument(1, 'string', 'null');
            if (isset($this->_meta[$key])) {
                return $this->_meta[$key];
            }return $this->_meta;
        }

        public function getQueryResponse() {
            $this->_meta['response'] = $this->getResponse();
            parse_str($this->_meta['response'], $response);
            return $response;
        }

        public function getResponse() {
            $curl = curl_init();
            $this->_addParameters()->_addHeaders();
            $this->_options[CURLOPT_RETURNTRANSFER] = true;
            curl_setopt_array($curl, $this->_options);
            $response = curl_exec($curl);
            $this->_meta = array('info' => curl_getinfo($curl, CURLINFO_HTTP_CODE), 'error_message' => curl_errno($curl), 'error_code' => curl_error($curl));
            curl_close($curl);
            unset($curl);
            return $response;
        }

        public function getSimpleXmlResponse() {
            $this->_meta['response'] = $this->getResponse();
            return simplexml_load_string($this->_meta['response']);
        }

        public function offsetExists($offset) {
            return isset($this->_option[$offset]);
        }

        public function offsetGet($offset) {
            return isset($this->_option[$offset]) ? $this->_option[$offset] : NULL;
        }

        public function offsetSet($offset, $value) {
            if (!is_null($offset)) {
                if (in_array($offset, $this->_setBoolKeys)) {
                    $method = array_search($offset, $this->_setBoolKeys);
                    $this->_call('set' . $method, array($value));
                }if (in_array($offset, $this->_setIntegerKeys)) {
                    $method = array_search($offset, $this->_setIntegerKeys);
                    $this->_call('set' . $method, array($value));
                }if (in_array($offset, $this->_setStringKeys)) {
                    $method = array_search($offset, $this->_setStringKeys);
                    $this->_call('set' . $method, array($value));
                }if (in_array($offset, $this->_setArrayKeys)) {
                    $method = array_search($offset, $this->_setArrayKeys);
                    $this->_call('set' . $method, array($value));
                }if (in_array($offset, $this->_setFileKeys)) {
                    $method = array_search($offset, $this->_setFileKeys);
                    $this->_call('set' . $method, array($value));
                }if (in_array($offset, $this->_setCallbackKeys)) {
                    $method = array_search($offset, $this->_setCallbackKeys);
                    $this->_call('set' . $method, array($value));
                }
            }
        }

        public function offsetUnset($offset) {
            unset($this->_option[$offset]);
        }

        public function send() {
            $curl = curl_init();
            $this->_addParameters()->_addHeaders();
            curl_setopt_array($curl, $this->_options);
            curl_exec($curl);
            $this->_meta = array('info' => curl_getinfo($curl, CURLINFO_HTTP_CODE), 'error_message' => curl_errno($curl), 'error_code' => curl_error($curl));
            curl_close($curl);
            unset($curl);
            return $this;
        }

        public function setCustomGet() {
            $this->setCustomRequest(self::GET);
            return $this;
        }

        public function setCustomPost() {
            $this->setCustomRequest(self::POST);
            return $this;
        }

        public function setCustomPut() {
            $this->setCustomRequest(self::PUT);
            return $this;
        }

        public function setCustomDelete() {
            $this->setCustomRequest(self::DELETE);
            return $this;
        }

        public function setPostFields($fields) {
            Eden_Curl_Error::i()->argument(1, 'array', 'string');
            $this->_options[CURLOPT_POSTFIELDS] = $fields;
            return $this;
        }

        public function setHeaders($key, $value = NULL) {
            Eden_Curl_Error::i()->argument(1, 'array', 'string')->argument(2, 'scalar', 'null');
            if (is_array($key)) {
                $this->_headers = $key;
                return $this;
            }$this->_headers[] = $key . ': ' . $value;
            return $this;
        }

        public function setUrlParameter($key, $value = NULL) {
            Eden_Curl_Error::i()->argument(1, 'array', 'string')->argument(2, 'scalar');
            if (is_array($key)) {
                $this->_param = $key;
                return $this;
            }$this->_param[$key] = $value;
        }

        public function verifyHost($on = true) {
            Eden_Curl_Error::i()->argument(1, 'bool');
            $this->_options[CURLOPT_SSL_VERIFYHOST] = $on ? 1 : 2;
            return $this;
        }

        public function verifyPeer($on = true) {
            Eden_Curl_Error::i()->argument(1, 'bool');
            $this->_options[CURLOPT_SSL_VERIFYPEER] = $on;
            return $this;
        }

        protected function _addHeaders() {
            if (empty($this->_headers)) {
                return $this;
            }$this->_options[CURLOPT_HTTPHEADER] = $this->_headers;
            return $this;
        }

        protected function _addParameters() {
            if (empty($this->_params)) {
                return $this;
            }$params = http_build_query($this->_params);
            if ($this->_options[CURLOPT_POST]) {
                $this->_options[CURLOPT_POSTFIELDS] = $params;
                return $this;
            }if (strpos($this->_options[CURLOPT_URL], '?') === false) {
                $params = '?' . $params;
            } else if (substr($this->_options[CURLOPT_URL], -1, 1) != '?') {
                $params = '&' . $params;
            }$this->_options[CURLOPT_URL].=$params;
            return $this;
        }

    }

    class Eden_Curl_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Path */
if (!class_exists('Eden_Path')) {

    class Eden_Path extends Eden_Type_String implements \ArrayAccess {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($path) {
            Eden_Path_Error::i()->argument(1, 'string');
            parent::__construct($this->_format($path));
        }

        public function __toString() {
            return $this->_data;
        }

        public function absolute($root = NULL) {
            Eden_Path_Error::i()->argument(1, 'string', 'null');
            if (is_dir($this->_data) || is_file($this->_data)) {
                return $this;
            }if (is_null($root)) {
                $root = $_SERVER['DOCUMENT_ROOT'];
            }$absolute = $this->_format($root) . $this->_data;
            if (is_dir($absolute) || is_file($absolute)) {
                $this->_data = $absolute;
                return $this;
            }Eden_Path_Error::i()->setMessage(Eden_Path_Error::FULL_PATH_NOT_FOUND)->addVariable($this->_data)->addVariable($absolute)->trigger();
        }

        public function append($path) {
            $error = Eden_Path_Error::i()->argument(1, 'string');
            $paths = func_get_args();
            foreach ($paths as $i => $path) {
                $error->argument($i + 1, $path, 'string');
                $this->_data.=$this->_format($path);
            }return $this;
        }

        public function getArray() {
            return explode('/', $this->_data);
        }

        public function offsetExists($offset) {
            return in_array($offset, $this->getArray());
        }

        public function offsetGet($offset) {
            $pathArray = $this->getArray();
            if ($offset == 'first') {
                $offset = 0;
            }if ($offset == 'last') {
                $offset = count($pathArray) - 1;
            }if (is_numeric($offset)) {
                return isset($pathArray[$offset]) ? $pathArray[$offset] : NULL;
            }return NULL;
        }

        public function offsetSet($offset, $value) {
            if (is_null($offset)) {
                $this->append($value);
            } else if ($offset == 'prepend') {
                $this->prepend($value);
            } else if ($offset == 'replace') {
                $this->replace($value);
            } else {
                $pathArray = $this->getArray();
                if ($offset > 0 && $offset < count($pathArray)) {
                    $pathArray[$offset] = $value;
                    $this->_data = implode('/', $pathArray);
                }
            }
        }

        public function offsetUnset($offset) {
            
        }

        public function prepend($path) {
            $error = Eden_Path_Error::i()->argument(1, 'string');
            $paths = func_get_args();
            foreach ($paths as $i => $path) {
                $error->argument($i + 1, $path, 'string');
                $this->_data = $this->_format($path) . $this->_data;
            }return $this;
        }

        public function pop() {
            $pathArray = $this->getArray();
            $path = array_pop($pathArray);
            $this->_data = implode('/', $pathArray);
            return $path;
        }

        public function replace($path) {
            Eden_Path_Error::i()->argument(1, 'string');
            $pathArray = $this->getArray();
            array_pop($pathArray);
            $pathArray[] = $path;
            $this->_data = implode('/', $pathArray);
            return $this;
        }

        protected function _format($path) {
            $path = str_replace('\\', '/', $path);
            $path = str_replace('//', '/', $path);
            if (substr($path, -1, 1) == '/') {
                $path = substr($path, 0, -1);
            }if (substr($path, 0, 1) != '/' && !preg_match("/^[A-Za-z]+\:/", $path)) {
                $path = '/' . $path;
            }return $path;
        }

    }

    class Eden_Path_Error extends Eden_Error {

        const FULL_PATH_NOT_FOUND = 'The path %s or %s was not found.';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_File */
if (!class_exists('Eden_File')) {

    class Eden_File extends Eden_Path {

        protected $_path = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function isFile() {
            return file_exists($this->_data);
        }

        public function getBase() {
            $pathInfo = pathinfo($this->_data);
            return $pathInfo['filename'];
        }

        public function getContent() {
            $this->absolute();
            if (!is_file($this->_data)) {
                Eden_File_Error::i()->setMessage(Eden_File_Error::PATH_IS_NOT_FILE)->addVariable($this->_data)->trigger();
            }return file_get_contents($this->_data);
        }

        public function getData() {
            $this->absolute();
            return include($this->_data);
        }

        public function getExtension() {
            $pathInfo = pathinfo($this->_data);
            if (!isset($pathInfo['extension'])) {
                return NULL;
            }return $pathInfo['extension'];
        }

        public function getFolder() {
            return dirname($this->_data);
        }

        public function getMime() {
            $this->absolute();
            if (function_exists('mime_content_type')) {
                return mime_content_type($this->_data);
            }if (function_exists('finfo_open')) {
                $resource = finfo_open(FILEINFO_MIME_TYPE);
                $mime = finfo_file($resource, $this->_data);
                finfo_close($finfo);
                return $mime;
            }$extension = strtolower($this->getExtension());
            $types = self::$_mimeTypes;
            if (isset($types[$extension])) {
                return $types[$extension];
            }return $types['class'];
        }

        public function getName() {
            return basename($this->_data);
        }

        public function getSize() {
            $this->absolute();
            return filesize($this->_data);
        }

        public function getTime() {
            $this->absolute();
            return filemtime($this->_data);
        }

        public function setContent($content) {
            Eden_File_Error::i()->argument(1, 'string');
            try {
                $this->absolute();
            } catch (Eden_Path_Error $e) {
                $this->touch();
            }file_put_contents($this->_data, $content);
            return $this;
        }

        public function setData($variable) {
            return $this->setContent(" //-->\nreturn " . var_export($variable, true) . ";");
        }

        public function remove() {
            $this->absolute();
            if (is_file($this->_data)) {
                unlink($this->_data);
                return $this;
            }return $this;
        }

        public function touch() {
            touch($this->_data);
            return $this;
        }

        protected static $_mimeTypes = array('ai' => 'application/postscript', 'aif' => 'audio/x-aiff', 'aifc' => 'audio/x-aiff', 'aiff' => 'audio/x-aiff', 'asc' => 'text/plain', 'atom' => 'application/atom+xml', 'au' => 'audio/basic', 'avi' => 'video/x-msvideo', 'bcpio' => 'application/x-bcpio', 'bin' => 'application/octet-stream', 'bmp' => 'image/bmp', 'cdf' => 'application/x-netcdf', 'cgm' => 'image/cgm', 'class' => 'application/octet-stream', 'cpio' => 'application/x-cpio', 'cpt' => 'application/mac-compactpro', 'csh' => 'application/x-csh', 'css' => 'text/css', 'dcr' => 'application/x-director', 'dif' => 'video/x-dv', 'dir' => 'application/x-director', 'djv' => 'image/vnd.djvu', 'djvu' => 'image/vnd.djvu', 'dll' => 'application/octet-stream', 'dmg' => 'application/octet-stream', 'dms' => 'application/octet-stream', 'doc' => 'application/msword', 'dtd' => 'application/xml-dtd', 'dv' => 'video/x-dv', 'dvi' => 'application/x-dvi', 'dxr' => 'application/x-director', 'eps' => 'application/postscript', 'etx' => 'text/x-setext', 'exe' => 'application/octet-stream', 'ez' => 'application/andrew-inset', 'gif' => 'image/gif', 'gram' => 'application/srgs', 'grxml' => 'application/srgs+xml', 'gtar' => 'application/x-gtar', 'hdf' => 'application/x-hdf', 'hqx' => 'application/mac-binhex40', 'htm' => 'text/html', 'html' => 'text/html', 'ice' => 'x-conference/x-cooltalk', 'ico' => 'image/x-icon', 'ics' => 'text/calendar', 'ief' => 'image/ief', 'ifb' => 'text/calendar', 'iges' => 'model/iges', 'igs' => 'model/iges', 'jnlp' => 'application/x-java-jnlp-file', 'jp2' => 'image/jp2', 'jpe' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'jpg' => 'image/jpeg', 'js' => 'application/x-javascript', 'kar' => 'audio/midi', 'latex' => 'application/x-latex', 'lha' => 'application/octet-stream', 'lzh' => 'application/octet-stream', 'm3u' => 'audio/x-mpegurl', 'm4a' => 'audio/mp4a-latm', 'm4b' => 'audio/mp4a-latm', 'm4p' => 'audio/mp4a-latm', 'm4u' => 'video/vnd.mpegurl', 'm4v' => 'video/x-m4v', 'mac' => 'image/x-macpaint', 'man' => 'application/x-troff-man', 'mathml' => 'application/mathml+xml', 'me' => 'application/x-troff-me', 'mesh' => 'model/mesh', 'mid' => 'audio/midi', 'midi' => 'audio/midi', 'mif' => 'application/vnd.mif', 'mov' => 'video/quicktime', 'movie' => 'video/x-sgi-movie', 'mp2' => 'audio/mpeg', 'mp3' => 'audio/mpeg', 'mp4' => 'video/mp4', 'mpe' => 'video/mpeg', 'mpeg' => 'video/mpeg', 'mpg' => 'video/mpeg', 'mpga' => 'audio/mpeg', 'ms' => 'application/x-troff-ms', 'msh' => 'model/mesh', 'mxu' => 'video/vnd.mpegurl', 'nc' => 'application/x-netcdf', 'oda' => 'application/oda', 'ogg' => 'application/ogg', 'pbm' => 'image/x-portable-bitmap', 'pct' => 'image/pict', 'pdb' => 'chemical/x-pdb', 'pdf' => 'application/pdf', 'pgm' => 'image/x-portable-graymap', 'pgn' => 'application/x-chess-pgn', 'pic' => 'image/pict', 'pict' => 'image/pict', 'png' => 'image/png', 'pnm' => 'image/x-portable-anymap', 'pnt' => 'image/x-macpaint', 'pntg' => 'image/x-macpaint', 'ppm' => 'image/x-portable-pixmap', 'ppt' => 'application/vnd.ms-powerpoint', 'ps' => 'application/postscript', 'qt' => 'video/quicktime', 'qti' => 'image/x-quicktime', 'qtif' => 'image/x-quicktime', 'ra' => 'audio/x-pn-realaudio', 'ram' => 'audio/x-pn-realaudio', 'ras' => 'image/x-cmu-raster', 'rdf' => 'application/rdf+xml', 'rgb' => 'image/x-rgb', 'rm' => 'application/vnd.rn-realmedia', 'roff' => 'application/x-troff', 'rtf' => 'text/rtf', 'rtx' => 'text/richtext', 'sgm' => 'text/sgml', 'sgml' => 'text/sgml', 'sh' => 'application/x-sh', 'shar' => 'application/x-shar', 'silo' => 'model/mesh', 'sit' => 'application/x-stuffit', 'skd' => 'application/x-koan', 'skm' => 'application/x-koan', 'skp' => 'application/x-koan', 'skt' => 'application/x-koan', 'smi' => 'application/smil', 'smil' => 'application/smil', 'snd' => 'audio/basic', 'so' => 'application/octet-stream', 'spl' => 'application/x-futuresplash', 'src' => 'application/x-wais-source', 'sv4cpio' => 'application/x-sv4cpio', 'sv4crc' => 'application/x-sv4crc', 'svg' => 'image/svg+xml', 'swf' => 'application/x-shockwave-flash', 't' => 'application/x-troff', 'tar' => 'application/x-tar', 'tcl' => 'application/x-tcl', 'tex' => 'application/x-tex', 'texi' => 'application/x-texinfo', 'texinfo' => 'application/x-texinfo', 'tif' => 'image/tiff', 'tiff' => 'image/tiff', 'tr' => 'application/x-troff', 'tsv' => 'text/tab-separated-values', 'txt' => 'text/plain', 'ustar' => 'application/x-ustar', 'vcd' => 'application/x-cdlink', 'vrml' => 'model/vrml', 'vxml' => 'application/voicexml+xml', 'wav' => 'audio/x-wav', 'wbmp' => 'image/vnd.wap.wbmp', 'wbmxl' => 'application/vnd.wap.wbxml', 'wml' => 'text/vnd.wap.wml', 'wmlc' => 'application/vnd.wap.wmlc', 'wmls' => 'text/vnd.wap.wmlscript', 'wmlsc' => 'application/vnd.wap.wmlscriptc', 'wrl' => 'model/vrml', 'xbm' => 'image/x-xbitmap', 'xht' => 'application/xhtml+xml', 'xhtml' => 'application/xhtml+xml', 'xls' => 'application/vnd.ms-excel', 'xml' => 'application/xml', 'xpm' => 'image/x-xpixmap', 'xsl' => 'application/xml', 'xslt' => 'application/xslt+xml', 'xul' => 'application/vnd.mozilla.xul+xml', 'xwd' => 'image/x-xwindowdump', 'xyz' => 'chemical/x-xyz', 'zip' => 'application/zip');

    }

    class Eden_File_Error extends Eden_Path_Error {

        const PATH_IS_NOT_FILE = 'Path %s is not a file in the system.';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Folder */
if (!class_exists('Eden_Folder')) {

    class Eden_Folder extends Eden_Path {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function create($chmod = 0755) {
            if (!is_int($chmod) || $chmod < 0 || $chmod > 777) {
                Eden_Folder_Error::i(Eden_Folder_Exception::CHMOD_IS_INVALID)->trigger();
            }if (!is_dir($this->_data)) {
                mkdir($this->_data, $chmod, true);
            }return $this;
        }

        public function getFiles($regex = NULL, $recursive = false) {
            $error = Eden_Folder_Error::i()->argument(1, 'string', 'null')->argument(2, 'bool');
            $this->absolute();
            $files = array();
            if ($handle = opendir($this->_data)) {
                while (false !== ($file = readdir($handle))) {
                    if (filetype($this->_data . '/' . $file) == 'file' && (!$regex || preg_match($regex, $file))) {
                        $files[] = Eden_File::i($this->_data . '/' . $file);
                    } else if ($recursive && $file != '.' && $file != '..' && filetype($this->_data . '/' . $file) == 'dir') {
                        $subfiles = self::i($this->_data . '/' . $file);
                        $files = array_merge($files, $subfiles->getFiles($regex, $recursive));
                    }
                }closedir($handle);
            }return $files;
        }

        public function getFolders($regex = NULL, $recursive = false) {
            Eden_Folder_Error::i()->argument(1, 'string', 'null')->argument(2, 'bool');
            $this->absolute();
            $folders = array();
            if ($handle = opendir($this->_data)) {
                while (false !== ($folder = readdir($handle))) {
                    if ($folder != '.' && $folder != '..' && filetype($this->_data . '/' . $folder) == 'dir' && (!$regex || preg_match($regex, $folder))) {
                        $folders[] = Eden_Folder::i($this->_data . '/' . $folder);
                        if ($recursive) {
                            $subfolders = Eden_Folder::i($this->_data . '/' . $folder);
                            $folders = array_merge($folders, $subfolders->getFolders($regex, $recursive));
                        }
                    }
                }closedir($handle);
            }return $folders;
        }

        public function getName() {
            $pathArray = $this->getArray();
            return array_pop($pathArray);
        }

        public function isFile() {
            return file_exists($this->_data);
        }

        public function isFolder($path = NULL) {
            Eden_Folder_Error::i()->argument(1, 'string', 'null');
            if (is_string($path)) {
                return is_dir($this->_data . '/' . $path);
            }return is_dir($this->_data);
        }

        public function remove() {
            $path = $this->absolute();
            if (is_dir($path)) {
                rmdir($path);
            }return $this;
        }

        public function removeFiles($regex = NULL) {
            Eden_Folder_Error::i()->argument(1, 'string', 'null');
            $files = $this->getFiles($regex);
            if (empty($files)) {
                return $this;
            }foreach ($files as $file) {
                $file->remove();
            }return $this;
        }

        public function removeFolders($regex = NULL) {
            Eden_Folder_Error::i()->argument(1, 'string', 'null');
            $this->absolute();
            $folders = $this->getFolders($regex);
            if (empty($folders)) {
                return $this;
            }foreach ($folders as $folder) {
                $folder->remove();
            }return $this;
        }

        public function truncate() {
            $this->removeFolders();
            $this->removeFiles();
            return $this;
        }

    }

    class Eden_Folder_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Block */
if (!class_exists('Eden_Block')) {

    abstract class Eden_Block extends \Eden {

        protected static $_blockRoot = NULL;
        private static $_global = array();

        public function __toString() {
            try {
                return (string) $this->render();
            } catch (Exception $e) {
                Eden_Error_Event::i()->exceptionHandler($e);
            }return '';
        }

        abstract public function getTemplate();

        abstract public function getVariables();

        public function render() {
            return Eden_Template::i()->set($this->getVariables())->parsePhp($this->getTemplate());
        }

        public function setBlockRoot($root) {
            Eden_Error::i()->argument(1, 'folder');
            self::$_blockRoot = $root;
            return $this;
        }

        protected function _getGlobal($value) {
            if (in_array($value, self::$_global)) {
                return false;
            }self::$_global[] = $value;
            return $value;
        }

    }

}
/* Eden_Model */
if (!class_exists('Eden_Model')) {

    class Eden_Model extends Eden_Type_Array {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        protected function _getMethodType(&$name) {
            return false;
        }

    }

    class Eden_Model_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden */
if (!class_exists('Eden')) {

    function eden() {
        $class = Eden::i();
        if (func_num_args() == 0) {
            return $class;
        }$args = func_get_args();
        return $class->__invoke($args);
    }

    class Eden extends Eden_Event {

        protected $_root = NULL;
        protected static $_active = NULL;

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function __construct() {
            if (!self::$_active) {
                self::$_active = $this;
            }$this->_root = dirname(__FILE__);
        }

        public function __call($name, $args) {
            try {
                return parent::__call($name, $args);
            } catch (Eden_Route_Exception $e) {
                return parent::__call('Eden_' . $name, $args);
            }
        }

        public function setRoot($root) {
            Eden_Error::i()->argument(1, 'string');
            if (!class_exists('Eden_Path')) {
                Eden_Loader::i()->load('Eden_Path');
            }$this->_root = (string) Eden_Path::i($root);
            return $this;
        }

        public function getRoot() {
            return $this->_root;
        }

        public function getActiveApp() {
            return self::$_active;
        }

        public function setLoader() {
            if (!class_exists('Eden_Loader')) {
                require_once dirname(__FILE__) . '/eden/loader.php';
            }spl_autoload_register(array(Eden_Loader::i(), 'handler'));
            if (!class_exists('Eden_Path')) {
                Eden_Loader::i()->addRoot(dirname(__FILE__))->load('Eden_Path');
            }$paths = func_get_args();
            if (empty($paths)) {
                return $this;
            }$paths = array_unique($paths);
            foreach ($paths as $i => $path) {
                if (!is_string($path) && !is_null($path)) {
                    continue;
                }if ($path) {
                    $path = (string) Eden_Path::i($path);
                } else {
                    $path = $this->_root;
                }if (!is_dir($path)) {
                    $path = $this->_root . $path;
                }if (is_dir($path)) {
                    Eden_Loader::i()->addRoot($path);
                }
            }return $this;
        }

        public function routeClasses($routes) {
            Eden_Error::i()->argument(1, 'string', 'array', 'bool');
            $route = Eden_Route::i()->getClass();
            if ($routes === true) {
                $route->route('Cache', 'Eden_Cache')->route('Registry', 'Eden_Registry')->route('Model', 'Eden_Model')->route('Collection', 'Eden_Collection')->route('Cookie', 'Eden_Cookie')->route('Session', 'Eden_Session')->route('Template', 'Eden_Template')->route('Curl', 'Eden_Curl')->route('Event', 'Eden_Event')->route('Path', 'Eden_Path')->route('File', 'Eden_File')->route('Folder', 'Eden_Folder')->route('Image', 'Eden_Image')->route('Mysql', 'Eden_Mysql')->route('Type', 'Eden_Type');
                return $this;
            }if (is_string($routes)) {
                $routes = include($routes);
            }foreach ($routes as $alias => $class) {
                $route->route($alias, $class);
            }return $this;
        }

        public function routeMethods($routes) {
            Eden_Error::i()->argument(1, 'string', 'array', 'bool');
            $route = Eden_Route::i()->getMethod();
            if (is_bool($routes)) {
                $route->route(NULL, 'output', 'Eden_Debug');
                return $this;
            }if (is_string($routes)) {
                $routes = include($routes);
            }foreach ($routes as $method => $routePath) {
                if (is_string($routePath)) {
                    $routePath = array($routePath);
                }if (is_array($routePath) && !empty($routePath)) {
                    if (count($routePath) == 1) {
                        $routePath[] = $method;
                    }$route->route($method, $routePath[0], $routePath[1]);
                }
            }return $this;
        }

        public function startSession() {
            Eden_Session::i()->start();
            return $this;
        }

        public function setTimezone($zone) {
            Eden_Error::i()->argument(1, 'string');
            date_default_timezone_set($zone);
            return $this;
        }

    }

}
/* Eden_Template */
if (!class_exists('Eden_Template')) {

    class Eden_Template extends \Eden {

        protected $_data = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function set($data, $value = NULL) {
            Eden_Template_Error::i()->argument(1, 'array', 'string');
            if (is_array($data)) {
                $this->_data = $data;
                return $this;
            }$this->_data[$data] = $value;
            return $this;
        }

        public function parseString($string) {
            Eden_Template_Error::i()->argument(1, 'string');
            foreach ($this->_data as $key => $value) {
                $string = str_replace($key, $value, $string);
            }return $string;
        }

        public function parsePhp($____file, $___evalString = false) {
            Eden_Template_Error::i()->argument(1, $____file, 'string')->argument(2, $___evalString, 'bool');
            extract($this->_data, EXTR_SKIP);
            if ($___evalString) {
                return eval('?>' . $___file . ';');
            }ob_start();
            include $____file;
            $____contents = ob_get_contents();
            ob_end_clean();
            return $____contents;
        }

    }

    class Eden_Template_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Session */
if (!class_exists('Eden_Session')) {

    class Eden_Session extends \Eden implements \ArrayAccess, \Iterator {

        protected static $_session = false;

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function __toString() {
            if (!self::$_session) {
                return '[]';
            }return json_encode($_SESSION);
        }

        public function clear() {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }$_SESSION = array();
            return $this;
        }

        public function current() {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }return current($_SESSION);
        }

        public function get($key = NULL) {
            $error = Eden_Session_Error::i()->argument(1, 'string', 'null');
            if (!self::$_session) {
                $error->setMessage(Eden_Session_Error::ERROR_ERROR_NOT_STARTED)->trigger();
            }if (is_null($key)) {
                return $_SESSION;
            }if (isset($_SESSION[$key])) {
                return $_SESSION[$key];
            }return NULL;
        }

        public function getId() {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }return session_id();
        }

        public function key() {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }return key($_SESSION);
        }

        public function next() {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }next($_SESSION);
        }

        public function offsetExists($offset) {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }return isset($_SESSION[$offset]);
        }

        public function offsetGet($offset) {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }return isset($_SESSION[$offset]) ? $_SESSION[$offset] : NULL;
        }

        public function offsetSet($offset, $value) {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }if (is_null($offset)) {
                $_SESSION[] = $value;
            } else {
                $_SESSION[$offset] = $value;
            }
        }

        public function offsetUnset($offset) {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }unset($_SESSION[$offset]);
        }

        public function remove($name) {
            Eden_Session_Error::i()->argument(1, 'string');
            if (isset($_SESSION[$name])) {
                unset($_SESSION[$name]);
            }return $this;
        }

        public function rewind() {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }reset($_SESSION);
        }

        public function set($data, $value = NULL) {
            $error = Eden_Session_Error::i()->argument(1, 'array', 'string');
            if (!self::$_session) {
                $error->setMessage(Eden_Session_Error::ERROR_ERROR_NOT_STARTED)->trigger();
            }if (is_array($data)) {
                $_SESSION = $data;
                return $this;
            }$_SESSION[$data] = $value;
            return $this;
        }

        public function setId($sid) {
            $error = Eden_Session_Error::i()->argument(1, 'numeric');
            if (!self::$_session) {
                $error->setMessage(Eden_Session_Error::ERROR_ERROR_NOT_STARTED)->trigger();
            }return session_id((int) $sid);
        }

        public function start() {
            if (!session_id()) {
                self::$_session = session_start();
            }return $this;
        }

        public function stop() {
            self::$_session = false;
            session_write_close();
            return $this;
        }

        public function valid() {
            if (!self::$_session) {
                Eden_Session_Error::i(Eden_Session_Error::ERROR_NOT_STARTED)->trigger();
            }return isset($_SESSION[$this->key()]);
        }

    }

    class Eden_Session_Error extends Eden_Error {

        const ERROR_NOT_STARTED = 'Session is not started.Try using Eden_Session->start() first.';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Cookie */
if (!class_exists('Eden_Cookie')) {

    class Eden_Cookie extends \Eden implements \ArrayAccess, \Iterator {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function clear() {
            foreach ($_COOKIE as $key => $value) {
                $this->remove($key);
            }return $this;
        }

        public function current() {
            return current($_COOKIE);
        }

        public function get($key = NULL) {
            Eden_Cookie_Error::i()->argument(1, 'string', 'null');
            if (is_null($key)) {
                return $_COOKIE;
            }if (isset($_COOKIE[$key])) {
                return $_COOKIE[$key];
            }return NULL;
        }

        public function key() {
            return key($_COOKIE);
        }

        public function next() {
            next($_COOKIE);
        }

        public function offsetExists($offset) {
            return isset($_COOKIE[$offset]);
        }

        public function offsetGet($offset) {
            return isset($_COOKIE[$offset]) ? $_COOKIE[$offset] : NULL;
        }

        public function offsetSet($offset, $value) {
            $this->set($offset, $value, strtotime('+10 years'));
        }

        public function offsetUnset($offset) {
            $this->remove($offset);
        }

        public function remove($name) {
            Eden_Cookie_Error::i()->argument(1, 'string');
            $this->set($name, NULL, time() - 3600);
            if (isset($_COOKIE[$name])) {
                unset($_COOKIE[$name]);
            }return $this;
        }

        public function rewind() {
            reset($_COOKIE);
        }

        public function set($key, $data = NULL, $expires = 0, $path = NULL, $domain = NULL, $secure = false, $httponly = false) {
            Eden_Cookie_Error::i()->argument(1, 'string')->argument(2, 'string', 'numeric', 'null')->argument(3, 'int')->argument(4, 'string', 'null')->argument(5, 'string', 'null')->argument(6, 'bool')->argument(7, 'bool');
            $_COOKIE[$key] = $data;
            setcookie($key, $data, $expires, $path, $domain, $secure, $httponly);
            return $this;
        }

        public function setData(array $data, $expires = 0, $path = NULL, $domain = NULL, $secure = false, $httponly = false) {
            foreach ($data as $key => $value) {
                $this->set($key, $value, $expires, $path, $domain, $secure, $httponly);
            }return $this;
        }

        public function setSecure($key, $data = NULL, $expires = 0, $path = NULL, $domain = NULL) {
            return $this->set($key, $data, $expires, $path, $domain, true, false);
        }

        public function setSecureData(array $data, $expires = 0, $path = NULL, $domain = NULL) {
            $this->set($data, $expires, $path, $domain, true, false);
            return $this;
        }

        public function valid() {
            return isset($_COOKIE[$this->key()]);
        }

    }

    class Eden_Cookie_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Registry */
if (!class_exists('Eden_Registry')) {

    class Eden_Registry extends Eden_Type_Array {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($data = array()) {
            if (func_num_args() > 1 || !is_array($data)) {
                $data = func_get_args();
            }foreach ($data as $key => $value) {
                if (!is_array($value)) {
                    continue;
                }$class = get_class($this);
                $data[$key] = $this->$class($value);
            }parent::__construct($data);
        }

        public function __toString() {
            return json_encode($this->getArray());
        }

        public function get($modified = true) {
            $args = func_get_args();
            if (count($args) == 0) {
                return $this;
            }$key = array_shift($args);
            if ($key === false) {
                if (count($args) == 0) {
                    return $this->getArray();
                }$modified = $key;
                $key = array_shift($args);
                array_unshift($args, $modified);
            }if (!isset($this->_data[$key])) {
                return NULL;
            }if (count($args) == 0) {
                return $this->_data[$key];
            }if ($this->_data[$key] instanceof Eden_Registry) {
                return call_user_func_array(array($this->_data[$key], __FUNCTION__), $args);
            }return NULL;
        }

        public function getArray($modified = true) {
            $array = array();
            foreach ($this->_data as $key => $data) {
                if ($data instanceof Eden_Registry) {
                    $array[$key] = $data->getArray($modified);
                    continue;
                }$array[$key] = $data;
            }return $array;
        }

        public function isKey() {
            $args = func_get_args();
            if (count($args) == 0) {
                return $this;
            }$key = array_shift($args);
            if (!isset($this->_data[$key])) {
                return false;
            }if (count($args) == 0) {
                return true;
            }if ($this->_data[$key] instanceof Eden_Registry) {
                return call_user_func_array(array($this->_data[$key], __FUNCTION__), $args);
            }return false;
        }

        public function offsetGet($offset) {
            if (!isset($this->_data[$offset])) {
                return NULL;
            }if ($this->_data[$offset] instanceof Eden_Registry) {
                return $this->_data[$offset]->getArray();
            }return $this->_data[$offset];
        }

        public function remove() {
            $args = func_get_args();
            if (count($args) == 0) {
                return $this;
            }$key = array_shift($args);
            if (!isset($this->_data[$key])) {
                return $this;
            }if (count($args) == 0) {
                unset($this->_data[$key]);
                return $this;
            }if ($this->_data[$key] instanceof Eden_Registry) {
                return call_user_func_array(array($this->_data[$key], __FUNCTION__), $args);
            }return $this;
        }

        public function set($value) {
            $args = func_get_args();
            if (count($args) < 2) {
                return $this;
            }$key = array_shift($args);
            if (count($args) == 1) {
                if (is_array($args[0])) {
                    $args[0] = self::i($args[0]);
                }$this->_data[$key] = $args[0];
                return $this;
            }if (!isset($this->_data[$key]) || !($this->_data[$key] instanceof Eden_Registry)) {
                $this->_data[$key] = self::i();
            }call_user_func_array(array($this->_data[$key], __FUNCTION__), $args);
            return $this;
        }

    }

}
/* Eden_Image */
if (!class_exists('Eden_Image')) {

    class Eden_Image extends \Eden {

        protected $_resource = NULL;
        protected $_width = 0;
        protected $_height = 0;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($data, $type = NULL, $path = true, $quality = 75) {
            Eden_Image_Error::i()->argument(1, 'string')->argument(2, 'string', 'null')->argument(3, 'bool')->argument(4, 'int');
            $this->_type = $type;
            $this->_quality = $quality;
            $this->_resource = $this->_getResource($data, $path);
            list($this->_width, $this->_height) = $this->getDimensions();
        }

        public function __destruct() {
            if ($this->_resource) {
                imagedestroy($this->_resource);
            }
        }

        public function __toString() {
            ob_start();
            switch ($this->_type) {
                case 'gif': imagegif($this->_resource);
                    break;
                case 'png': $quality = (100 - $this->_quality) / 10;
                    if ($quality > 9) {
                        $quality = 9;
                    }imagepng($this->_resource, NULL, $quality);
                    break;
                case 'bmp': case 'wbmp': imagewbmp($this->_resource, NULL, $this->_quality);
                    break;
                case 'jpg': case 'jpeg': case 'pjpeg': default: imagejpeg($this->_resource, NULL, $this->_quality);
                    break;
            }return ob_get_clean();
        }

        public function blur() {
            imagefilter($this->_resource, IMG_FILTER_SELECTIVE_BLUR);
            return $this;
        }

        public function brightness($level) {
            Eden_Image_Error::i()->argument(1, 'numeric');
            imagefilter($this->_resource, IMG_FILTER_BRIGHTNESS, $level);
            return $this;
        }

        public function colorize($red, $blue, $green, $alpha = 0) {
            Eden_Image_Error::i()->argument(1, 'numeric')->argument(2, 'numeric')->argument(3, 'numeric')->argument(4, 'numeric');
            imagefilter($this->_resource, IMG_FILTER_COLORIZE, $red, $blue, $green, $alpha);
            return $this;
        }

        public function contrast($level) {
            Eden_Image_Error::i()->argument(1, 'numeric');
            imagefilter($this->_resource, IMG_FILTER_CONTRAST, $level);
            return $this;
        }

        public function crop($width = NULL, $height = NULL) {
            Eden_Image_Error::i()->argument(1, 'numeric', 'null')->argument(2, 'numeric', 'null');
            $orgWidth = imagesx($this->_resource);
            $orgHeight = imagesy($this->_resource);
            if (is_null($width)) {
                $width = $orgWidth;
            }if (is_null($height)) {
                $height = $orgHeight;
            }if ($width == $orgWidth && $height == $orgHeight) {
                return $this;
            }$crop = imagecreatetruecolor($width, $height);
            $xPosition = 0;
            $yPosition = 0;
            if ($width > $orgWidth || $height > $orgHeight) {
                $newWidth = $width;
                $newHeight = $height;
                if ($height > $width) {
                    $height = $this->_getHeightAspectRatio($orgWidth, $orgHeight, $width);
                    if ($newHeight > $height) {
                        $height = $newHeight;
                        $width = $this->_getWidthAspectRatio($orgWidth, $orgHeight, $height);
                        $rWidth = $this->_getWidthAspectRatio($newWidth, $newHeight, $orgHeight);
                        $xPosition = ($orgWidth / 2) - ($rWidth / 2);
                    } else {
                        $rHeight = $this->_getHeightAspectRatio($newWidth, $newHeight, $orgWidth);
                        $yPosition = ($orgHeight / 2) - ($rHeight / 2);
                    }
                } else {
                    $width = $this->_getWidthAspectRatio($orgWidth, $orgHeight, $height);
                    if ($newWidth > $width) {
                        $width = $newWidth;
                        $height = $this->_getHeightAspectRatio($orgWidth, $orgHeight, $width);
                        $rHeight = $this->_getHeightAspectRatio($newWidth, $newHeight, $orgWidth);
                        $yPosition = ($orgHeight / 2) - ($rHeight / 2);
                    } else {
                        $rWidth = $this->_getWidthAspectRatio($newWidth, $newHeight, $orgHeight);
                        $xPosition = ($orgWidth / 2) - ($rWidth / 2);
                    }
                }
            } else {
                if ($width < $orgWidth) {
                    $xPosition = ($orgWidth / 2) - ($width / 2);
                    $width = $orgWidth;
                }if ($height < $orgHeight) {
                    $yPosition = ($orgHeight / 2) - ($height / 2);
                    $height = $orgHeight;
                }
            }imagecopyresampled($crop, $this->_resource, 0, 0, $xPosition, $yPosition, $width, $height, $orgWidth, $orgHeight);
            imagedestroy($this->_resource);
            $this->_resource = $crop;
            return $this;
        }

        public function edgedetect() {
            imagefilter($this->_resource, IMG_FILTER_EDGEDETECT);
            return $this;
        }

        public function emboss() {
            imagefilter($this->_resource, IMG_FILTER_EMBOSS);
            return $this;
        }

        public function gaussianBlur() {
            imagefilter($this->_resource, IMG_FILTER_GAUSSIAN_BLUR);
            return $this;
        }

        public function getDimensions() {
            return array(imagesx($this->_resource), imagesy($this->_resource));
        }

        public function getResource() {
            return $this->_resource;
        }

        public function greyscale() {
            imagefilter($this->_resource, IMG_FILTER_GRAYSCALE);
            return $this;
        }

        public function invert($vertical = false) {
            Eden_Image_Error::i()->argument(1, 'bool');
            $orgWidth = imagesx($this->_resource);
            $orgHeight = imagesy($this->_resource);
            $invert = imagecreatetruecolor($orgWidth, $orgHeight);
            if ($vertical) {
                imagecopyresampled($invert, $this->_resource, 0, 0, 0, ($orgHeight - 1), $orgWidth, $orgHeight, $orgWidth, 0 - $orgHeight);
            } else {
                imagecopyresampled($invert, $this->_resource, 0, 0, ($orgWidth - 1), 0, $orgWidth, $orgHeight, 0 - $orgWidth, $orgHeight);
            }imagedestroy($this->_resource);
            $this->_resource = $invert;
            return $this;
        }

        public function meanRemoval() {
            imagefilter($this->_resource, IMG_FILTER_MEAN_REMOVAL);
            return $this;
        }

        public function negative() {
            imagefilter($this->_resource, IMG_FILTER_NEGATE);
            return $this;
        }

        public function resize($width = NULL, $height = NULL) {
            Eden_Image_Error::i()->argument(1, 'numeric', 'null')->argument(2, 'numeric', 'null');
            $orgWidth = imagesx($this->_resource);
            $orgHeight = imagesy($this->_resource);
            if (is_null($width)) {
                $width = $orgWidth;
            }if (is_null($height)) {
                $height = $orgHeight;
            }if ($width == $orgWidth && $height == $orgHeight) {
                return $this;
            }$newWidth = $width;
            $newHeight = $height;
            if ($height < $width) {
                $width = $this->_getWidthAspectRatio($orgWidth, $orgHeight, $height);
                if ($newWidth < $width) {
                    $width = $newWidth;
                    $height = $this->_getHeightAspectRatio($orgWidth, $orgHeight, $width);
                }
            } else {
                $height = $this->_getHeightAspectRatio($orgWidth, $orgHeight, $width);
                if ($newHeight < $height) {
                    $height = $newHeight;
                    $width = $this->_getWidthAspectRatio($orgWidth, $orgHeight, $height);
                }
            }return $this->scale($width, $height);
        }

        public function rotate($degree, $background = 0) {
            Eden_Image_Error::i()->argument(1, 'numeric')->argument(2, 'numeric');
            $rotate = imagerotate($this->_resource, $degree, $background);
            imagedestroy($this->_resource);
            $this->_resource = $rotate;
            return $this;
        }

        public function scale($width = NULL, $height = NULL) {
            Eden_Image_Error::i()->argument(1, 'numeric', 'null')->argument(2, 'numeric', 'null');
            $orgWidth = imagesx($this->_resource);
            $orgHeight = imagesy($this->_resource);
            if (is_null($width)) {
                $width = $orgWidth;
            }if (is_null($height)) {
                $height = $orgHeight;
            }if ($width == $orgWidth && $height == $orgHeight) {
                return $this;
            }$scale = imagecreatetruecolor($width, $height);
            imagecopyresampled($scale, $this->_resource, 0, 0, 0, 0, $width, $height, $orgWidth, $orgHeight);
            imagedestroy($this->_resource);
            $this->_resource = $scale;
            return $this;
        }

        public function setTransparency() {
            imagealphablending($this->_resource, false);
            imagesavealpha($this->_resource, true);
            return $this;
        }

        public function smooth($level) {
            Eden_Image_Error::i()->argument(1, 'numeric');
            imagefilter($this->_resource, IMG_FILTER_SMOOTH, $level);
            return $this;
        }

        public function save($path, $type = NULL) {
            if (!$type) {
                $type = $this->_type;
            }switch ($type) {
                case 'gif': imagegif($this->_resource, $path);
                    break;
                case 'png': $quality = (100 - $this->_quality) / 10;
                    if ($quality > 9) {
                        $quality = 9;
                    }imagepng($this->_resource, $path, $quality);
                    break;
                case 'bmp': case 'wbmp': imagewbmp($this->_resource, $path, $this->_quality);
                    break;
                case 'jpg': case 'jpeg': case 'pjpeg': default: imagejpeg($this->_resource, $path, $this->_quality);
                    break;
            }return $this;
        }

        protected function _getHeightAspectRatio($sourceWidth, $sourceHeight, $destinationWidth) {
            $ratio = $destinationWidth / $sourceWidth;
            return $sourceHeight * $ratio;
        }

        protected function _getResource($data, $path) {
            if (!function_exists('gd_info')) {
                Eden_Image_Error::i(Eden_Image_Error::GD_NOT_INSTALLED)->trigger();
            }$resource = false;
            if (!$path) {
                return imagecreatefromstring($data);
            }switch ($this->_type) {
                case 'gd': $resource = imagecreatefromgd($data);
                    break;
                case 'gif': $resource = imagecreatefromgif($data);
                    break;
                case 'jpg': case 'jpeg': case 'pjpeg': $resource = imagecreatefromjpeg($data);
                    break;
                case 'png': $resource = imagecreatefrompng($data);
                    break;
                case 'bmp': case 'wbmp': $resource = imagecreatefromwbmp($data);
                    break;
                case 'xbm': $resource = imagecreatefromxbm($data);
                    break;
                case 'xpm': $resource = imagecreatefromxpm($data);
                    break;
            }if (!$resource) {
                Eden_Image_Error::i()->setMessage(Eden_Image_Error::NOT_VALID_IMAGE_FILE)->addVariable($path);
            }return $resource;
        }

        protected function _getWidthAspectRatio($sourceWidth, $sourceHeight, $destinationHeight) {
            $ratio = $destinationHeight / $sourceHeight;
            return $sourceWidth * $ratio;
        }

    }

    class Eden_Image_Error extends Eden_Error {

        const GD_NOT_INSTALLED = 'PHP GD Library is not installed.';
        const NOT_VALID_IMAGE_FILE = '%s is not a valid image file.';
        const NOT_STRING_MODEL = 'Argument %d is expecting a string or Eden_Image_Model.';

    }

}
/* Eden_Unit */
if (!class_exists('Eden_Unit')) {

    class Eden_Unit {

        protected $_last = array();
        protected $_start = 0;
        protected $_end = 0;
        protected $_report = array();
        protected $_package = 'main';

        public static function i() {
            $class = __CLASS__;
            return new $class();
        }

        public function __construct() {
            $this->_start = time();
        }

        public function __destruct() {
            $this->_end = time();
        }

        public function __call($name, $args) {
            if (method_exists($this, '_' . $name)) {
                $method = '_' . $name;
                $message = array_pop($args);
                $test = array('name' => $name, 'start' => isset($this->_last['end']) ? $this->_last['end'] : $this->_start, 'message' => $message);
                try {
                    $test['pass'] = call_user_func_array(array(&$this, $method), $args);
                } catch (Exception $e) {
                    $test['pass'] = false;
                    $test['error'] = array(get_class($e), $e->getMessage());
                }$test['end'] = time();
                $test['trace'] = debug_backtrace();
                $this->_report[$this->_package][] = $this->_last = $test;
                return $this;
            }
        }

        public function getPassFail($package = NULL) {
            Eden_Unit_Error::i()->argument(1, 'string', 'null');
            $passFail = array(0, 0);
            if (isset($this->_report[$package])) {
                foreach ($this->_report[$package] as $test) {
                    if ($test['pass']) {
                        $passFail[0]++;
                        continue;
                    }$passFail[1]++;
                }return $passFail;
            }foreach ($this->_report as $package => $tests) {
                $packagePassFail = $this->getPassFail($package);
                $passFail[0] +=$packagePassFail[0];
                $passFail[1] +=$packagePassFail[1];
            }return $passFail;
        }

        public function getReport() {
            return $this->_report;
        }

        public function getTotalTests($package = NULL) {
            Eden_Unit_Error::i()->argument(1, 'string', 'null');
            if (isset($this->_report[$package])) {
                return count($this->_report[$package]);
            }$total = 0;
            foreach ($this->_report as $package => $tests) {
                $total +=$tests;
            }return $tests;
        }

        public function setPackage($name) {
            Eden_Unit_Error::i()->argument(1, 'string');
            $this->_package = $name;
            return $this;
        }

        protected function _assertArrayHasKey($needle, $haystack) {
            try {
                Eden_Unit_Error::i()->argument(1, 'string')->argument(2, 'array');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return array_key_exists($needle, $haystack);
        }

        protected function _assertClassHasAttribute($needle, $haystack) {
            try {
                Eden_Unit_Error::i()->argument(1, 'string')->argument(2, 'object', 'string');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return property_exists($needle, $haystack);
        }

        protected function _assertContains($needle, $haystack) {
            try {
                Eden_Unit_Error::i()->argument(1, 'string')->argument(2, 'array', 'string');
            } catch (Eden_Unit_Error $e) {
                return false;
            }if (is_string($haystack)) {
                return strstr($haystack, $needle) !== false;
            }return in_array($needle, $haystack);
        }

        protected function _assertContainsOnly($type, $haystack) {
            try {
                Eden_Unit_Error::i()->argument(1, 'string')->argument(2, 'object', 'array');
            } catch (Eden_Unit_Error $e) {
                return false;
            }$method = 'is_' . $type;
            if (function_exists($method)) {
                foreach ($haystack as $needle) {
                    if (!$method($needle)) {
                        return false;
                    }
                }return true;
            }if (class_exists($type)) {
                foreach ($haystack as $needle) {
                    if (get_class($needle) != $type) {
                        return false;
                    }
                }return true;
            }return false;
        }

        protected function _assertCount($number, $haystack) {
            try {
                Eden_Unit_Error::i()->argument(1, 'int')->argument(2, 'array', 'string');
            } catch (Eden_Unit_Error $e) {
                return false;
            }if (is_string($haystack)) {
                return strlen($haystack) == $number;
            }return count($haystack) == $number;
        }

        protected function _assertEmpty($actual) {
            return empty($actual);
        }

        protected function _assertEquals($expected, $actual) {
            return $expected === $actual;
        }

        protected function _assertFalse($condition) {
            return $condition === false;
        }

        protected function _assertGreaterThan($number, $actual) {
            try {
                Eden_Unit_Error::i()->argument(1, 'numeric')->argument(2, 'numeric');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return $actual > $number;
        }

        protected function _assertGreaterThanOrEqual($number, $actual) {
            try {
                Eden_Unit_Error::i()->argument(1, 'numeric')->argument(2, 'numeric');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return $actual >= $number;
        }

        protected function _assertInstanceOf($expected, $actual) {
            try {
                Eden_Unit_Error::i()->argument(1, 'string')->argument(2, 'object');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return $actual instanceof $expected;
        }

        protected function _assertInternalType($type, $actual) {
            try {
                Eden_Unit_Error::i()->argument(1, 'string');
            } catch (Eden_Unit_Error $e) {
                return false;
            }$method = 'is_' . $type;
            if (function_exists($method)) {
                return !$method($actual);
            }if (class_exists($type)) {
                return get_class($actual) != $type;
            }return false;
        }

        protected function _assertLessThan($number, $actual) {
            try {
                Eden_Unit_Error::i()->argument(1, 'numeric')->argument(2, 'numeric');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return $actual < $number;
        }

        protected function _assertLessThanOrEqual($number, $actual) {
            try {
                Eden_Unit_Error::i()->argument(1, 'numeric')->argument(2, 'numeric');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return $actual <= $number;
        }

        protected function _assertNull($mixed) {
            return is_null($mixed);
        }

        protected function _assertRegExp($pattern, $string) {
            try {
                Eden_Unit_Error::i()->argument(1, 'string')->argument(2, 'string');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return preg_match($pattern, $string);
        }

        protected function _assertSame($expected, $actual) {
            return $expected == $actual;
        }

        protected function _assertStringEndsWith($suffix, $string) {
            try {
                Eden_Unit_Error::i()->argument(1, 'string')->argument(2, 'string');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return substr_compare($string, $suffix, -strlen($suffix), strlen($suffix)) === 0;
        }

        protected function _assertStringStartsWith($prefix, $string) {
            try {
                Eden_Unit_Error::i()->argument(1, 'string')->argument(2, 'string');
            } catch (Eden_Unit_Error $e) {
                return false;
            }return strpos($string, $prefix) === 0;
        }

        protected function _assertTrue($condition) {
            return $condition === true;
        }

    }

    class Eden_Unit_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Timezone_Error */
if (!class_exists('Eden_Timezone_Error')) {

    class Eden_Timezone_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

        protected function _isValid($type, $data) {
            $valid = Eden_Timezone_Validation::i();
            switch ($type) {
                case 'location': return $valid->isLocation($data);
                case 'utc': return $valid->isUtc($data);
                case 'abbr': return $valid->isAbbr($data);
                default: break;
            }return parent::_isValid($type, $data);
        }

    }

}
/* Eden_Timezone_Validation */
if (!class_exists('Eden_Timezone_Validation')) {

    class Eden_Timezone_Validation extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function isAbbr($value) {
            return preg_match('/^[A-Z]{1,5}$/', $value);
        }

        public function isLocation($value) {
            return in_array($value, DateTimeZone::listIdentifiers());
        }

        public function isUtc($value) {
            return preg_match('/^(GMT|UTC){0,1}(\-|\+)[0-9]{1,2}(\:{0,1}[0-9]{2}){0,1}$/', $value);
        }

    }

}
/* Eden_Timezone */
if (!class_exists('Eden_Timezone')) {

    class Eden_Timezone extends \Eden {

        const GMT = 'GMT';
        const UTC = 'UTC';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($zone, $time = NULL) {
            Eden_Timezone_Error::i()->argument(1, 'string')->argument(1, 'location', 'utc', 'abbr')->argument(2, 'int', 'string', 'null');
            if (is_null($time)) {
                $time = time();
            }$this->_offset = $this->_getOffset($zone);
            $this->setTime($time);
        }

        public function convertTo($zone, $format = NULL) {
            Eden_Timezone_Error::i()->argument(1, 'string')->argument(1, 'location', 'utc', 'abbr')->argument(2, 'string', 'null');
            $time = $this->_time + $this->_getOffset($zone);
            if (!is_null($format)) {
                return date($format, $time);
            }return $time;
        }

        public function getGMT($prefix = self::GMT) {
            Eden_Timezone_Error::i()->argument(1, 'string');
            list($hour, $minute, $sign) = $this->_getUtcParts($this->_offset);
            return $prefix . $sign . $hour . $minute;
        }

        public function getGMTDates($format, $interval = 30, $prefix = self::GMT) {
            Eden_Timezone_Error::i()->argument(1, 'string')->argument(2, 'int')->argument(3, 'string', 'null');
            $offsets = $this->getOffsetDates($format, $interval);
            $dates = array();
            foreach ($offsets as $offset => $date) {
                list($hour, $minute, $sign) = $this->_getUtcParts($offset);
                $gmt = $prefix . $sign . $hour . $minute;
                $dates[$gmt] = $date;
            }return $dates;
        }

        public function getOffset() {
            return $this->_offset;
        }

        public function getOffsetDates($format, $interval = 30) {
            Eden_Timezone_Error::i()->argument(1, 'string')->argument(2, 'int');
            $dates = array();
            $interval *=60;
            for ($i = -12 * 3600; $i <= (12 * 3600); $i+=$interval) {
                $time = $this->_time + $i;
                $dates[$i] = date($format, $time);
            }return $dates;
        }

        public function getTime($format = NULL) {
            Eden_Timezone_Error::i()->argument(1, 'string', 'null');
            $time = $this->_time + $this->_offset;
            if (!is_null($format)) {
                return date($format, $time);
            }return $time;
        }

        public function getUTC($prefix = self::UTC) {
            Eden_Timezone_Error::i()->argument(1, 'string');
            list($hour, $minute, $sign) = $this->_getUtcParts($this->_offset);
            return $prefix . $sign . $hour . ':' . $minute;
        }

        public function getUTCDates($format, $interval = 30, $prefix = self::UTC) {
            Eden_Timezone_Error::i()->argument(1, 'string')->argument(2, 'int')->argument(3, 'string', 'null');
            $offsets = $this->getOffsetDates($format, $interval);
            $dates = array();
            foreach ($offsets as $offset => $date) {
                list($hour, $minute, $sign) = $this->_getUtcParts($offset);
                $utc = $prefix . $sign . $hour . ':' . $minute;
                $dates[$utc] = $date;
            }return $dates;
        }

        public function setTime($time) {
            Eden_Timezone_Error::i()->argument(1, 'int', 'string');
            if (is_string($time)) {
                $time = strtotime($time);
            }$this->_time = $time - $this->_offset;
            return $this;
        }

        public function validation() {
            return Eden_Timezone_Validation::i();
        }

        protected function _getOffset($zone) {
            if ($this->validation()->isLocation($zone)) {
                return $this->_getOffsetFromLocation($zone);
            }if ($this->validation()->isUtc($zone)) {
                return $this->_getOffsetFromUtc($zone);
            }if ($this->validation()->isAbbr($zone)) {
                return $this->_getOffsetFromAbbr($zone);
            }return 0;
        }

        protected function _getOffsetFromAbbr($zone) {
            $zone = timezone_name_from_abbr(strtolower($zone));
            return $this->_getOffsetFromLocation($zone);
        }

        protected function _getOffsetFromLocation($zone) {
            $zone = new DateTimeZone($zone);
            $gmt = new DateTimeZone(self::GMT);
            return $zone->getOffset(new DateTime('now', $gmt));
        }

        protected function _getOffsetFromUtc($zone) {
            $zone = str_replace(array('GMT', 'UTC'), '', $zone);
            $zone = str_replace(':', '', $zone);
            $add = $zone[0] == '+';
            $zone = substr($zone, 1);
            switch (strlen($zone)) {
                case 1: case 2: return $zone * 3600 * ($add ? 1 : -1);
                case 3: $hour = substr($zone, 0, 1) * 3600;
                    $minute = substr($zone, 1) * 60;
                    return ($hour + $minute) * ($add ? 1 : -1);
                case 4: $hour = substr($zone, 0, 2) * 3600;
                    $minute = substr($zone, 2) * 60;
                    return ($hour + $minute) * ($add ? 1 : -1);
            }return 0;
        }

        private function _getUtcParts($offset) {
            $minute = '0' . (floor(abs($offset / 60)) % 60);
            return array(floor(abs($offset / 3600)), substr($minute, strlen($minute) - 2), $offset < 0 ? '-' : '+');
        }

    }

}
/* Eden_Country_Error */
if (!class_exists('Eden_Country_Error')) {

    class Eden_Country_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Country_Au */
if (!class_exists('Eden_Country_Au')) {

    class Eden_Country_Australia extends \Eden {

        protected static $_territories = array('Australian Capital Territory', 'New South Wales', 'Northern Territory', 'Queensland', 'South Australia', 'Tasmania', 'Victoria', 'Western Australia');

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function getTerritories() {
            return self::$_territories;
        }

    }

}
/* Eden_Country_Ca */
if (!class_exists('Eden_Country_Ca')) {

    class Eden_Country_Ca extends \Eden {

        protected static $_territories = array('BC' => 'British Columbia', 'ON' => 'Ontario', 'NL' => 'Newfoundland and Labrador', 'NS' => 'Nova Scotia', 'PE' => 'Prince Edward Island', 'NB' => 'New Brunswick', 'QC' => 'Quebec', 'MB' => 'Manitoba', 'SK' => 'Saskatchewan', 'AB' => 'Alberta', 'NT' => 'Northwest Territories', 'NU' => 'Nunavut', 'YT' => 'Yukon Territory');

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function getTerritories() {
            return self::$_territories;
        }

    }

}
/* Eden_Country_Uk */
if (!class_exists('Eden_Country_Uk')) {

    class Eden_Country_Uk extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function getCounties() {
            return self::$_counties;
        }

        protected static $_counties = array('Aberdeenshire', 'Alderney', 'Angus/Forfarshire', 'Argyllshire', 'Avon', 'Ayrshire', 'Banffshire', 'Bedfordshire', 'Berkshire', 'Berwickshire', 'Buckinghamshire', 'Buteshire', 'Caithness', 'Cambridgeshire', 'Cheshire', 'Clackmannanshire', 'Clwyd', 'Cornwall', 'County Antrim', 'County Armagh', 'County Down', 'County Fermanagh', 'County Londonderry', 'County Tyrone', 'Cumbria', 'Derbyshire', 'Devon', 'Dorset', 'Dumbartonshire', 'Dumfriesshire', 'Durham', 'Dyfed', 'East Lothian', 'East Sussex', 'East Yorkshire', 'Essex', 'Fair Isle', 'Fife', 'Gloucestershire', 'Greater London', 'Greater Manchester', 'Guernsey', 'Gwent', 'Gwynedd', 'Hampshire', 'Herefordshire', 'Herm', 'Hertfordshire', 'Huntingdonshire', 'Inner Hebrides', 'Inverness-shire', 'Isle of Man', 'Isle of Wight', 'Isles of Scilly', 'Jersey', 'Kent', 'Kincardineshire', 'Kinross-shire', 'Kirkcudbrightshire', 'Lanarkshire', 'Lancashire', 'Leicestershire', 'Lincolnshire', 'Merseyside', 'Mid Glamorgan', 'Middlesex', 'Midlothian/Edinburghshire', 'Morayshire', 'Nairnshire', 'Norfolk', 'North Yorkshire', 'Northamptonshire', 'Northumberland', 'Nottinghamshire', 'Orkney', 'Outer Hebrides', 'Oxfordshire', 'Peeblesshire', 'Perthshire', 'Powys', 'Renfrewshire', 'Ross-shire', 'Roxburghshire', 'Rutland', 'Sark', 'Selkirkshire', 'Shetland', 'Shropshire', 'Somerset', 'South Glamorgan', 'South Yorkshire', 'Staffordshire', 'Stirlingshire', 'Suffolk', 'Surrey', 'Sutherland', 'Tyne and Wear', 'Warwickshire', 'West Glamorgan', 'West Lothian/Linlithgowshire', 'West Midlands', 'West Sussex', 'West Yorkshire', 'Wigtownshire', 'Wiltshire', 'Worcestershire');

    }

}
/* Eden_Country_Us */
if (!class_exists('Eden_Country_Us')) {

    class Eden_Country_Us extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function getStateFromPostal($postal) {
            Eden_Country_Error::i()->argument(1, 'int');
            if (strlen((string) $postal) < 5) {
                return false;
            }for ($i = 0; $i < count(self::$_codes); $i++) {
                if ($postal < substr(self::$_codes[$i], 2, 5) || $postal > substr(self::$_codes[$i], 7, 5)) {
                    continue;
                }return substr(self::$_codes[$i], 0, 2);
            }return false;
        }

        public function getStates() {
            return self::$_states;
        }

        public function getTerritories() {
            return self::$_territories;
        }

        protected static $_codes = array('AK9950099929', 'AL3500036999', 'AR7160072999', 'AR7550275505', 'AZ8500086599', 'CA9000096199', 'CO8000081699', 'CT0600006999', 'DC2000020099', 'DC2020020599', 'DE1970019999', 'FL3200033999', 'FL3410034999', 'GA3000031999', 'HI9670096798', 'HI9680096899', 'IA5000052999', 'ID8320083899', 'IL6000062999', 'IN4600047999', 'KS6600067999', 'KY4000042799', 'KY4527545275', 'LA7000071499', 'LA7174971749', 'MA0100002799', 'MD2033120331', 'MD2060021999', 'ME0380103801', 'ME0380403804', 'ME0390004999', 'MI4800049999', 'MN5500056799', 'MO6300065899', 'MS3860039799', 'MT5900059999', 'NC2700028999', 'ND5800058899', 'NE6800069399', 'NH0300003803', 'NH0380903899', 'NJ0700008999', 'NM8700088499', 'NV8900089899', 'NY0040000599', 'NY0639006390', 'NY0900014999', 'OH4300045999', 'OK7300073199', 'KY7340074999', 'OR9700097999', 'PA1500019699', 'RI0280002999', 'RI0637906379', 'SC2900029999', 'SD5700057799', 'TN3700038599', 'TN7239572395', 'TX7330073399', 'TX7394973949', 'TX7500079999', 'TX8850188599', 'UT8400084799', 'VA2010520199', 'VA2030120301', 'VA2037020370', 'VA2200024699', 'VT0500005999', 'WA9800099499', 'WI4993649936', 'WI5300054999', 'WV2470026899', 'WY8200083199');
        protected static $_states = array('AL' => 'Alabama', 'AK' => 'Alaska', 'AZ' => 'Arizona', 'AR' => 'Arkansas', 'CA' => 'California', 'CO' => 'Colorado', 'CT' => 'Connecticut', 'DE' => 'Delaware', 'DC' => 'District Of Columbia', 'FL' => 'Florida', 'GA' => 'Georgia', 'HI' => 'Hawaii', 'ID' => 'Idaho', 'IL' => 'Illinois', 'IN' => 'Indiana', 'IA' => 'Iowa', 'KS' => 'Kansas', 'KY' => 'Kentucky', 'LA' => 'Louisiana', 'ME' => 'Maine', 'MD' => 'Maryland', 'MA' => 'Massachusetts', 'MI' => 'Michigan', 'MN' => 'Minnesota', 'MS' => 'Mississippi', 'MO' => 'Missouri', 'MT' => 'Montana', 'NE' => 'Nebraska', 'NV' => 'Nevada', 'NH' => 'New Hampshire', 'NJ' => 'New Jersey', 'NM' => 'New Mexico', 'NY' => 'New York', 'NC' => 'North Carolina', 'ND' => 'North Dakota', 'OH' => 'Ohio', 'OK' => 'Oklahoma', 'OR' => 'Oregon', 'PA' => 'Pennsylvania', 'RI' => 'Rhode Island', 'SC' => 'South Carolina', 'SD' => 'South Dakota', 'TN' => 'Tennessee', 'TX' => 'Texas', 'UT' => 'Utah', 'VT' => 'Vermont', 'VA' => 'Virginia', 'WA' => 'Washington', 'WV' => 'West Virginia', 'WI' => 'Wisconsin', 'WY' => 'Wyoming');
        protected static $_territories = array('AS' => 'American Samoa', 'FM' => 'Federated States of Micronesia', 'GU' => 'Guam', 'MH' => 'Marshall Islands', 'MP' => 'Northern Mariana Islands', 'PW' => 'Palau', 'PR' => 'Puerto Rico', 'VI' => 'Virgin Islands', 'AE' => 'Armed Forces', 'AA' => 'Armed Forces Americas', 'AP' => 'Armed Forces Pacific');

    }

}
/* Eden_Country */
if (!class_exists('Eden_Country')) {

    class Eden_Country extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function au() {
            return Eden_Country_Au::i();
        }

        public function ca() {
            return Eden_Country_Ca::i();
        }

        public function getList() {
            return self::$_countries;
        }

        public function uk() {
            return Eden_Country_Uk::i();
        }

        public function us() {
            return Eden_Country_Us::i();
        }

        protected static $_countries = array('GB' => 'United Kingdom', 'US' => 'United States', 'AF' => 'Afghanistan', 'AL' => 'Albania', 'DZ' => 'Algeria', 'AS' => 'American Samoa', 'AD' => 'Andorra', 'AO' => 'Angola', 'AI' => 'Anguilla', 'AQ' => 'Antarctica', 'AG' => 'Antigua And Barbuda', 'AR' => 'Argentina', 'AM' => 'Armenia', 'AW' => 'Aruba', 'AU' => 'Australia', 'AT' => 'Austria', 'AZ' => 'Azerbaijan', 'BS' => 'Bahamas', 'BH' => 'Bahrain', 'BD' => 'Bangladesh', 'BB' => 'Barbados', 'BY' => 'Belarus', 'BE' => 'Belgium', 'BZ' => 'Belize', 'BJ' => 'Benin', 'BM' => 'Bermuda', 'BT' => 'Bhutan', 'BO' => 'Bolivia', 'BA' => 'Bosnia And Herzegowina', 'BW' => 'Botswana', 'BV' => 'Bouvet Island', 'BR' => 'Brazil', 'IO' => 'British Indian Ocean Territory', 'BN' => 'Brunei Darussalam', 'BG' => 'Bulgaria', 'BF' => 'Burkina Faso', 'BI' => 'Burundi', 'KH' => 'Cambodia', 'CM' => 'Cameroon', 'CA' => 'Canada', 'CV' => 'Cape Verde', 'KY' => 'Cayman Islands', 'CF' => 'Central African Republic', 'TD' => 'Chad', 'CL' => 'Chile', 'CN' => 'China', 'CX' => 'Christmas Island', 'CC' => 'Cocos (Keeling) Islands', 'CO' => 'Colombia', 'KM' => 'Comoros', 'CG' => 'Congo', 'CD' => 'Congo,The Democratic Republic Of The', 'CK' => 'Cook Islands', 'CR' => 'Costa Rica', 'CI' => 'Cote D\'Ivoire', 'HR' => 'Croatia (Local Name: Hrvatska)', 'CU' => 'Cuba', 'CY' => 'Cyprus', 'CZ' => 'Czech Republic', 'DK' => 'Denmark', 'DJ' => 'Djibouti', 'DM' => 'Dominica', 'DO' => 'Dominican Republic', 'TP' => 'East Timor', 'EC' => 'Ecuador', 'EG' => 'Egypt', 'SV' => 'El Salvador', 'GQ' => 'Equatorial Guinea', 'ER' => 'Eritrea', 'EE' => 'Estonia', 'ET' => 'Ethiopia', 'FK' => 'Falkland Islands (Malvinas)', 'FO' => 'Faroe Islands', 'FJ' => 'Fiji', 'FI' => 'Finland', 'FR' => 'France', 'FX' => 'France,Metropolitan', 'GF' => 'French Guiana', 'PF' => 'French Polynesia', 'TF' => 'French Southern Territories', 'GA' => 'Gabon', 'GM' => 'Gambia', 'GE' => 'Georgia', 'DE' => 'Germany', 'GH' => 'Ghana', 'GI' => 'Gibraltar', 'GR' => 'Greece', 'GL' => 'Greenland', 'GD' => 'Grenada', 'GP' => 'Guadeloupe', 'GU' => 'Guam', 'GT' => 'Guatemala', 'GN' => 'Guinea', 'GW' => 'Guinea-Bissau', 'GY' => 'Guyana', 'HT' => 'Haiti', 'HM' => 'Heard And Mc Donald Islands', 'VA' => 'Holy See (Vatican City State)', 'HN' => 'Honduras', 'HK' => 'Hong Kong', 'HU' => 'Hungary', 'IS' => 'Iceland', 'IN' => 'India', 'ID' => 'Indonesia', 'IR' => 'Iran (Islamic Republic Of)', 'IQ' => 'Iraq', 'IE' => 'Ireland', 'IL' => 'Israel', 'IT' => 'Italy', 'JM' => 'Jamaica', 'JP' => 'Japan', 'JO' => 'Jordan', 'KZ' => 'Kazakhstan', 'KE' => 'Kenya', 'KI' => 'Kiribati', 'KP' => 'Korea,Democratic People\'s Republic Of', 'KR' => 'Korea,Republic Of', 'KW' => 'Kuwait', 'KG' => 'Kyrgyzstan', 'LA' => 'Lao People\'s Democratic Republic', 'LV' => 'Latvia', 'LB' => 'Lebanon', 'LS' => 'Lesotho', 'LR' => 'Liberia', 'LY' => 'Libyan Arab Jamahiriya', 'LI' => 'Liechtenstein', 'LT' => 'Lithuania', 'LU' => 'Luxembourg', 'MO' => 'Macau', 'MK' => 'Macedonia,Former Yugoslav Republic Of', 'MG' => 'Madagascar', 'MW' => 'Malawi', 'MY' => 'Malaysia', 'MV' => 'Maldives', 'ML' => 'Mali', 'MT' => 'Malta', 'MH' => 'Marshall Islands', 'MQ' => 'Martinique', 'MR' => 'Mauritania', 'MU' => 'Mauritius', 'YT' => 'Mayotte', 'MX' => 'Mexico', 'FM' => 'Micronesia,Federated States Of', 'MD' => 'Moldova,Republic Of', 'MC' => 'Monaco', 'MN' => 'Mongolia', 'MS' => 'Montserrat', 'MA' => 'Morocco', 'MZ' => 'Mozambique', 'MM' => 'Myanmar', 'NA' => 'Namibia', 'NR' => 'Nauru', 'NP' => 'Nepal', 'NL' => 'Netherlands', 'AN' => 'Netherlands Antilles', 'NC' => 'New Caledonia', 'NZ' => 'New Zealand', 'NI' => 'Nicaragua', 'NE' => 'Niger', 'NG' => 'Nigeria', 'NU' => 'Niue', 'NF' => 'Norfolk Island', 'MP' => 'Northern Mariana Islands', 'NO' => 'Norway', 'OM' => 'Oman', 'PK' => 'Pakistan', 'PW' => 'Palau', 'PA' => 'Panama', 'PG' => 'Papua New Guinea', 'PY' => 'Paraguay', 'PE' => 'Peru', 'PH' => 'Philippines', 'PN' => 'Pitcairn', 'PL' => 'Poland', 'PT' => 'Portugal', 'PR' => 'Puerto Rico', 'QA' => 'Qatar', 'RE' => 'Reunion', 'RO' => 'Romania', 'RU' => 'Russian Federation', 'RW' => 'Rwanda', 'KN' => 'Saint Kitts And Nevis', 'LC' => 'Saint Lucia', 'VC' => 'Saint Vincent And The Grenadines', 'WS' => 'Samoa', 'SM' => 'San Marino', 'ST' => 'Sao Tome And Principe', 'SA' => 'Saudi Arabia', 'SN' => 'Senegal', 'SC' => 'Seychelles', 'SL' => 'Sierra Leone', 'SG' => 'Singapore', 'SK' => 'Slovakia (Slovak Republic)', 'SI' => 'Slovenia', 'SB' => 'Solomon Islands', 'SO' => 'Somalia', 'ZA' => 'South Africa', 'GS' => 'South Georgia,South Sandwich Islands', 'ES' => 'Spain', 'LK' => 'Sri Lanka', 'SH' => 'St.Helena', 'PM' => 'St.Pierre And Miquelon', 'SD' => 'Sudan', 'SR' => 'Suriname', 'SJ' => 'Svalbard And Jan Mayen Islands', 'SZ' => 'Swaziland', 'SE' => 'Sweden', 'CH' => 'Switzerland', 'SY' => 'Syrian Arab Republic', 'TW' => 'Taiwan', 'TJ' => 'Tajikistan', 'TZ' => 'Tanzania,United Republic Of', 'TH' => 'Thailand', 'TG' => 'Togo', 'TK' => 'Tokelau', 'TO' => 'Tonga', 'TT' => 'Trinidad And Tobago', 'TN' => 'Tunisia', 'TR' => 'Turkey', 'TM' => 'Turkmenistan', 'TC' => 'Turks And Caicos Islands', 'TV' => 'Tuvalu', 'UG' => 'Uganda', 'UA' => 'Ukraine', 'AE' => 'United Arab Emirates', 'UM' => 'United States Minor Outlying Islands', 'UY' => 'Uruguay', 'UZ' => 'Uzbekistan', 'VU' => 'Vanuatu', 'VE' => 'Venezuela', 'VN' => 'Viet Nam', 'VG' => 'Virgin Islands (British)', 'VI' => 'Virgin Islands (U.S.)', 'WF' => 'Wallis And Futuna Islands', 'EH' => 'Western Sahara', 'YE' => 'Yemen', 'YU' => 'Yugoslavia', 'ZM' => 'Zambia', 'ZW' => 'Zimbabwe');

    }

}
/* Eden_Language */
if (!class_exists('Eden_Language')) {

    class Eden_Language extends \Eden implements \ArrayAccess, \Iterator {

        protected $_language = array();
        protected $_file = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($language = array()) {
            Eden_Language_Error::i()->argument(1, 'file', 'array');
            if (is_string($language)) {
                $this->_file = $language;
                $language = include($language);
            }$this->_language = $language;
        }

        public function current() {
            return current($this->_language);
        }

        public function get($key) {
            Eden_Language_Error::i()->argument(1, 'string');
            if (!isset($this->_language[$key])) {
                $this->_language[$key] = $key;
            }return $this->_language[$key];
        }

        public function getLanguage() {
            return $this->_language;
        }

        public function key() {
            return key($this->_language);
        }

        public function next() {
            next($this->_language);
        }

        public function offsetExists($offset) {
            return isset($this->_language[$offset]);
        }

        public function offsetGet($offset) {
            return $this->get($offset);
        }

        public function offsetSet($offset, $value) {
            $this->translate($offset, $value);
        }

        public function offsetUnset($offset) {
            unset($this->_language[$offset]);
        }

        public function rewind() {
            reset($this->_language);
        }

        public function save($file = NULL) {
            Eden_Language_Error::i()->argument(1, 'file', 'null');
            if (is_null($file)) {
                $file = $this->_file;
            }if (is_null($file)) {
                Eden_Language_Error::i()->setMessage(Eden_Language_Error::INVALID_ARGUMENT)->addVariable(1)->addVariable(__CLASS__ . '->' . __FUNCTION__)->addVariable('file or null')->addVariable($file)->setTypeLogic()->trigger();
            }Eden_File::i($file)->setData($this->_language);
            return $this;
        }

        public function translate($key, $value) {
            Eden_Language_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_language[$key] = $value;
            return $this;
        }

        public function valid() {
            return isset($this->_language[key($this->_language)]);
        }

    }

    class Eden_Language_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Oauth_Error */
if (!class_exists('Eden_Oauth_Error')) {

    class Eden_Oauth_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Oauth_Base */
if (!class_exists('Eden_Oauth_Base')) {

    class Eden_Oauth_Base extends \Eden {

        const HMAC_SHA1 = 'HMAC-SHA1';
        const RSA_SHA1 = 'RSA-SHA1';
        const PLAIN_TEXT = 'PLAINTEXT';
        const POST = 'POST';
        const GET = 'GET';
        const OAUTH_VERSION = '1.0';

        protected function _buildQuery($params, $separator = '&', $noQuotes = true, $subList = false) {
            if (empty($params)) {
                return '';
            }$keys = $this->_encode(array_keys($params));
            $values = $this->_encode(array_values($params));
            $params = array_combine($keys, $values);
            uksort($params, 'strcmp');
            foreach ($params as $key => $value) {
                if (is_array($value)) {
                    natsort($value);
                    $params[$key] = $this->_buildQuery($value, $separator, $noQuotes, true);
                    continue;
                }if (!$noQuotes) {
                    $value = '"' . $value . '"';
                }$params[$key] = $value;
            }if ($subList) {
                return $params;
            }foreach ($params as $key => $value) {
                $params[$key] = $key . '=' . $value;
            }return implode($separator, $params);
        }

        protected function _encode($string) {
            if (is_array($string)) {
                foreach ($string as $i => $value) {
                    $string[$i] = $this->_encode($value);
                }return $string;
            }if (is_scalar($string)) {
                return str_replace('%7E', '~', rawurlencode($string));
            }return NULL;
        }

        protected function _decode($raw_input) {
            return rawurldecode($raw_input);
        }

        protected function _parseString($string) {
            $array = array();
            if (strlen($string) < 1) {
                return $array;
            }$keyvalue = explode('&', $query_string);
            foreach ($keyvalue as $pair) {
                list($k, $v) = explode('=', $pair, 2);
                if (isset($query_array[$k])) {
                    if (is_scalar($query_array[$k])) {
                        $query_array[$k] = array($query_array[$k]);
                    }array_push($query_array[$k], $v);
                } else {
                    $query_array[$k] = $v;
                }
            }return $array;
        }

    }

}
/* Eden_Oauth_Consumer */
if (!class_exists('Eden_Oauth_Consumer')) {

    class Eden_Oauth_Consumer extends Eden_Oauth_Base {

        const AUTH_HEADER = 'Authorization: OAuth %s';
        const POST_HEADER = 'Content-Type: application/x-www-form-urlencoded';

        protected $_consumerKey = NULL;
        protected $_consumerSecret = NULL;
        protected $_requestToken = NULL;
        protected $_requestSecret = NULL;
        protected $_useAuthorization = false;
        protected $_url = NULL;
        protected $_method = NULL;
        protected $_realm = NULL;
        protected $_time = NULL;
        protected $_nonce = NULL;
        protected $_verifier = NULL;
        protected $_callback = NULL;
        protected $_signature = NULL;
        protected $_meta = array();
        protected $_headers = array();
        protected $_json = false;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($url, $key, $secret) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_consumerKey = $key;
            $this->_consumerSecret = $secret;
            $this->_url = $url;
            $this->_time = time();
            $this->_nonce = md5(uniqid(rand(), true));
            $this->_signature = self::PLAIN_TEXT;
            $this->_method = self::GET;
        }

        public function getAuthorization($signature, $string = true) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'bool');
            $params = array('realm' => $this->_realm, 'oauth_consumer_key' => $this->_consumerKey, 'oauth_token' => $this->_requestToken, 'oauth_signature_method' => self::HMAC_SHA1, 'oauth_signature' => $signature, 'oauth_timestamp' => $this->_time, 'oauth_nonce' => $this->_nonce, 'oauth_version' => self::OAUTH_VERSION, 'oauth_verifier' => $this->_verifier, 'oauth_callback' => $this->_callback);
            if (is_null($this->_realm)) {
                unset($params['realm']);
            }if (is_null($this->_requestToken)) {
                unset($params['oauth_token']);
            }if (is_null($this->_verifier)) {
                unset($params['oauth_verifier']);
            }if (is_null($this->_callback)) {
                unset($params['oauth_callback']);
            }if (!$string) {
                return $params;
            }return sprintf(self::AUTH_HEADER, $this->_buildQuery($params, ',', false));
        }

        public function getDomDocumentResponse(array $query = array()) {
            $xml = new DOMDocument();
            $xml->loadXML($this->getResponse($query));
            return $xml;
        }

        public function getHmacPlainTextSignature() {
            return $this->_consumerSecret . '&' . $this->_tokenSecret;
        }

        public function getHmacSha1Signature(array $query = array()) {
            $params = array('oauth_consumer_key' => $this->_consumerKey, 'oauth_token' => $this->_requestToken, 'oauth_signature_method' => self::HMAC_SHA1, 'oauth_timestamp' => $this->_time, 'oauth_nonce' => $this->_nonce, 'oauth_version' => self::OAUTH_VERSION, 'oauth_verifier' => $this->_verifier, 'oauth_callback' => $this->_callback);
            if (is_null($this->_requestToken)) {
                unset($params['oauth_token']);
            }if (is_null($this->_verifier)) {
                unset($params['oauth_verifier']);
            }if (is_null($this->_callback)) {
                unset($params['oauth_callback']);
            }$query = array_merge($params, $query);
            $query = $this->_buildQuery($query);
            $string = array($this->_method, $this->_encode($this->_url), $this->_encode($query));
            $string = implode('&', $string);
            $key = $this->_encode($this->_consumerSecret) . '&' . $this->_encode($this->_requestSecret);
            return base64_encode(hash_hmac('sha1', $string, $key, true));
        }

        public function getJsonResponse(array $query = array(), $assoc = true) {
            return json_decode($this->getResponse($query), $assoc);
        }

        public function getMeta($key = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string', 'null');
            if (isset($this->_meta[$key])) {
                return $this->_meta[$key];
            }return $this->_meta;
        }

        public function getQueryResponse(array $query = array()) {
            parse_str($this->getResponse($query), $response);
            return $response;
        }

        public function getResponse(array $query = array()) {
            $headers = $this->_headers;
            $json = NULL;
            if ($this->_json) {
                $json = json_encode($query);
                $query = array();
            }$signature = $this->getSignature($query);
            $authorization = $this->getAuthorization($signature, false);
            if ($this->_useAuthorization) {
                $headers[] = sprintf(self::AUTH_HEADER, $this->_buildQuery($authorization, ',', false));
            } else {
                $query = array_merge($authorization, $query);
            }$query = $this->_buildQuery($query);
            $url = $this->_url;
            $curl = Eden_Curl::i()->verifyHost(false)->verifyPeer(false);
            if ($this->_method == self::POST) {
                $headers[] = self::POST_HEADER;
                if (!is_null($json)) {
                    $query = $json;
                }$response = $curl->setUrl($url)->setPost(true)->setPostFields($query)->setHeaders($headers)->getResponse();
            } else {
                if (trim($query)) {
                    $connector = NULL;
                    if (strpos($url, '?') === false) {
                        $connector = '?';
                    } else if (substr($url, -1) != '?') {
                        $connector = '&';
                    }$url.=$connector . $query;
                }$response = $curl->setUrl($url)->setHeaders($headers)->getResponse();
            }$this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['authorization'] = $authorization;
            $this->_meta['headers'] = $headers;
            $this->_meta['query'] = $query;
            $this->_meta['response'] = $response;
            return $response;
        }

        public function getSignature(array $query = array()) {
            switch ($this->_signature) {
                case self::HMAC_SHA1: return $this->getHmacSha1Signature($query);
                case self::RSA_SHA1: case self::PLAIN_TEXT: default: return $this->getHmacPlainTextSignature();
            }
        }

        public function getSimpleXmlResponse(array $query = array()) {
            return simplexml_load_string($this->getResponse($query));
        }

        public function jsonEncodeQuery() {
            $this->_json = true;
            return $this;
        }

        public function setCallback($url) {
            Eden_Oauth_Error::i()->argument(1, 'string');
            $this->_callback = $url;
            return $this;
        }

        public function setHeaders($key, $value = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'array', 'string')->argument(2, 'scalar', 'null');
            if (is_array($key)) {
                $this->_headers = $key;
                return $this;
            }$this->_headers[] = $key . ': ' . $value;
            return $this;
        }

        public function setMethodToGet() {
            $this->_method = self::GET;
            return $this;
        }

        public function setMethodToPost() {
            $this->_method = self::POST;
            return $this;
        }

        public function setRealm($realm) {
            Eden_Oauth_Error::i()->argument(1, 'string');
            $this->_realm = $realm;
            return $this;
        }

        public function setSignatureToHmacSha1() {
            $this->_signature = self::HMAC_SHA1;
            return $this;
        }

        public function setSignatureToRsaSha1() {
            $this->_signature = self::RSA_SHA1;
            return $this;
        }

        public function setSignatureToPlainText() {
            $this->_signature = self::PLAIN_TEXT;
            return $this;
        }

        public function setToken($token, $secret) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_requestToken = $token;
            $this->_requestSecret = $secret;
            return $this;
        }

        public function setVerifier($verifier) {
            Eden_Oauth_Error::i()->argument(1, 'scalar');
            $this->_verifier = $verifier;
            return $this;
        }

        public function useAuthorization($use = true) {
            Eden_Oauth_Error::i()->argument(1, 'bool');
            $this->_useAuthorization = $use;
            return $this;
        }

    }

}
/* Eden_Oauth */
if (!class_exists('Eden_Oauth')) {

    class Eden_Oauth extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function consumer($url, $key, $secret) {
            return Eden_Oauth_Consumer::i($url, $key, $secret);
        }

        public function getHmacGetAccessToken($url, $key, $secret, $token, $tokenSecret, array $query = array(), $realm = NULL, $verifier = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string')->argument(7, 'string', 'null')->argument(8, 'string', 'null');
            return $this->consumer($url, $key, $secret)->setMethodToGet()->setSignatureToHmacSha1()->when($realm)->setRealm($realm)->endWhen()->when($verifier)->setVerifier($verifier)->endWhen()->setRequestToken($token, $tokenSecret)->getToken($query);
        }

        public function getHmacGetAuthorizationAccessToken($url, $key, $secret, $token, $tokenSecret, array $query = array(), $realm = NULL, $verifier = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string')->argument(7, 'string', 'null')->argument(8, 'string', 'null');
            return $this->consumer($url, $key, $secret)->useAuthorization()->setMethodToGet()->setSignatureToHmacSha1()->when($realm)->setRealm($realm)->endWhen()->when($verifier)->setVerifier($verifier)->endWhen()->setRequestToken($token, $tokenSecret)->getToken($query);
        }

        public function getHmacGetAuthorizationRequestToken($url, $key, $secret, array $query = array(), $realm = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(5, 'string', 'null');
            return $this->consumer($url, $key, $secret)->useAuthorization()->setMethodToGet()->setSignatureToHmacSha1()->when($realm)->setRealm($realm)->endWhen()->getToken($query);
        }

        public function getHmacGetRequestToken($url, $key, $secret, array $query = array(), $realm = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(5, 'string', 'null');
            return $this->consumer($url, $key, $secret)->setMethodToGet()->setSignatureToHmacSha1()->when($realm)->setRealm($realm)->endWhen()->getToken($query);
        }

        public function getHmacPostAccessToken($url, $key, $secret, $token, $tokenSecret, array $query = array(), $realm = NULL, $verifier = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string')->argument(7, 'string', 'null')->argument(8, 'string', 'null');
            return $this->consumer($url, $key, $secret)->setMethodToPost()->setSignatureToHmacSha1()->when($realm)->setRealm($realm)->endWhen()->when($verifier)->setVerifier($verifier)->endWhen()->setRequestToken($token, $tokenSecret)->getToken($query);
        }

        public function getHmacPostAuthorizationAccessToken($url, $key, $secret, $token, $tokenSecret, array $query = array(), $realm = NULL, $verifier = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string')->argument(7, 'string', 'null')->argument(8, 'string', 'null');
            return $this->consumer($url, $key, $secret)->useAuthorization()->setMethodToPost()->setSignatureToHmacSha1()->when($realm)->setRealm($realm)->endWhen()->when($verifier)->setVerifier($verifier)->endWhen()->setRequestToken($token, $tokenSecret)->getToken($query);
        }

        public function getHmacPostAuthorizationRequestToken($url, $key, $secret, array $query = array(), $realm = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(5, 'string', 'null');
            return $this->consumer($url, $key, $secret)->useAuthorization()->setMethodToPost()->setSignatureToHmacSha1()->when($realm)->setRealm($realm)->endWhen()->getToken($query);
        }

        public function getHmacPostRequestToken($url, $key, $secret, array $query = array(), $realm = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(5, 'string', 'null');
            return $this->consumer($url, $key, $secret)->setMethodToPost()->setSignatureToHmacSha1()->when($realm)->setRealm($realm)->endWhen()->getToken($query);
        }

        public function getPlainGetAccessToken($url, $key, $secret, $token, $tokenSecret, array $query = array(), $realm = NULL, $verifier = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string')->argument(7, 'string', 'null')->argument(8, 'string', 'null');
            return $this->consumer($url, $key, $secret)->setMethodToGet()->setSignatureToPlainText()->when($realm)->setRealm($realm)->endWhen()->when($verifier)->setVerifier($verifier)->endWhen()->setRequestToken($token, $tokenSecret)->getToken($query);
        }

        public function getPlainGetAuthorizationAccessToken($url, $key, $secret, $token, $tokenSecret, array $query = array(), $realm = NULL, $verifier = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string')->argument(7, 'string', 'null')->argument(8, 'string', 'null');
            return $this->consumer($url, $key, $secret)->useAuthorization()->setMethodToGet()->setSignatureToPlainText()->when($realm)->setRealm($realm)->endWhen()->when($verifier)->setVerifier($verifier)->endWhen()->setRequestToken($token, $tokenSecret)->getToken($query);
        }

        public function getPlainGetAuthorizationRequestToken($url, $key, $secret, array $query = array(), $realm = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(5, 'string', 'null');
            return $this->consumer($url, $key, $secret)->useAuthorization()->setMethodToGet()->setSignatureToPlainText()->when($realm)->setRealm($realm)->endWhen()->getToken($query);
        }

        public function getPlainGetRequestToken($url, $key, $secret, array $query = array(), $realm = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(5, 'string', 'null');
            return $this->consumer($url, $key, $secret)->setMethodToGet()->setSignatureToPlainText()->when($realm)->setRealm($realm)->endWhen()->getToken($query);
        }

        public function getPlainPostAccessToken($url, $key, $secret, $token, $tokenSecret, array $query = array(), $realm = NULL, $verifier = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string')->argument(7, 'string', 'null')->argument(8, 'string', 'null');
            return $this->consumer($url, $key, $secret)->setMethodToPost()->setSignatureToPlainText()->when($realm)->setRealm($realm)->endWhen()->when($verifier)->setVerifier($verifier)->endWhen()->setRequestToken($token, $tokenSecret)->getToken($query);
        }

        public function getPlainPostAuthorizationAccessToken($url, $key, $secret, $token, $tokenSecret, array $query = array(), $realm = NULL, $verifier = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string')->argument(7, 'string', 'null')->argument(8, 'string', 'null');
            return $this->consumer($url, $key, $secret)->useAuthorization()->setMethodToPost()->setSignatureToPlainText()->when($realm)->setRealm($realm)->endWhen()->when($verifier)->setVerifier($verifier)->endWhen()->setRequestToken($token, $tokenSecret)->getToken($query);
        }

        public function getPlainPostAuthorizationRequestToken($url, $key, $secret, array $query = array(), $realm = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(5, 'string', 'null');
            return $this->consumer($url, $key, $secret)->useAuthorization()->setMethodToPost()->setSignatureToPlainText()->when($realm)->setRealm($realm)->endWhen()->getToken($query);
        }

        public function getPlainPostRequestToken($url, $key, $secret, array $query = array(), $realm = NULL) {
            Eden_Oauth_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(5, 'string', 'null');
            return $this->consumer($url, $key, $secret)->setMethodToPost()->setSignatureToPlainText()->when($realm)->setRealm($realm)->endWhen()->getToken($query);
        }

        public function server() {
            return Eden_Oauth_Server::i();
        }

    }

}
/* Eden_Oauth2_Abstract */
if (!class_exists('Eden_Oauth2_Abstract')) {

    abstract class Eden_Oauth2_Abstract extends \Eden {

        const CODE = 'code';
        const TOKEN = 'token';
        const ONLINE = 'online';
        const OFFLINE = 'offline';
        const AUTO = 'auto';
        const FORCE = 'force';
        const TYPE = 'Content-Type';
        const REQUEST = 'application/x-www-form-urlencoded';
        const RESPONSE_TYPE = 'response_type';
        const CLIENT_ID = 'client_id';
        const REDIRECT_URL = 'redirect_uri';
        const ACCESS_TYPE = 'access_type';
        const APROVAL = 'approval_prompt';
        const CLIENT_SECRET = 'client_secret';
        const GRANT_TYPE = 'grant_type';
        const AUTHORIZATION = 'authorization_code';

        protected $_client = NULL;
        protected $_secret = NULL;
        protected $_redirect = NULL;
        protected $_state = NULL;
        protected $_scope = NULL;
        protected $_display = NULL;
        protected $_requestUrl = NULL;
        protected $_accessUrl = NULL;
        protected $_responseType = self::CODE;
        protected $_approvalPrompt = self::AUTO;

        public function __construct($client, $secret, $redirect, $requestUrl, $accessUrl) {
            Eden_Oauth2_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'url')->argument(4, 'url')->argument(5, 'url');
            $this->_client = $client;
            $this->_secret = $secret;
            $this->_redirect = $redirect;
            $this->_requestUrl = $requestUrl;
            $this->_accessUrl = $accessUrl;
        }

        public function autoApprove() {
            $this->_approvalPrompt = self::AUTO;
            return $this;
        }

        public function forceApprove() {
            $this->_approvalPrompt = self::FORCE;
            return $this;
        }

        public function setState($state) {
            Eden_Oauth2_Error::i()->argument(1, 'string');
            $this->_state = $state;
            return $this;
        }

        public function setScope($scope) {
            Eden_Oauth2_Error::i()->argument(1, 'string', 'array');
            $this->_scope = $scope;
            return $this;
        }

        public function setDisplay($display) {
            Eden_Oauth2_Error::i()->argument(1, 'string', 'array');
            $this->_display = $display;
            return $this;
        }

        public function isJson($string) {
            Eden_Oauth2_Error::i()->argument(1, 'string');
            json_decode($string);
            return (json_last_error() == JSON_ERROR_NONE);
        }

        abstract public function getLoginUrl($scope = NULL, $display = NULL);

        abstract public function getAccess($code);

        protected function _getLoginUrl($query) {
            if (!is_null($this->_scope)) {
                if (is_array($this->_scope)) {
                    $this->_scope = implode(' ', $this->_scope);
                }$query['scope'] = $this->_scope;
            }if (!is_null($this->_state)) {
                $query['state'] = $this->_state;
            }if (!is_null($this->_display)) {
                $query['display'] = $this->_display;
            }return $this->_requestUrl . '?' . http_build_query($query);
        }

        protected function _getAccess($query, $code = NULL) {
            if (!is_null($code)) {
                $query[self::CODE] = $code;
            }$result = Eden_Curl::i()->setUrl($this->_accessUrl)->verifyHost(false)->verifyPeer(false)->setHeaders(self::TYPE, self::REQUEST)->setPostFields(http_build_query($query))->getResponse();
            if ($this->isJson($result)) {
                $response = json_decode($result, true);
            } else {
                parse_str($result, $response);
            }return $response;
        }

    }

}
/* Eden_Oauth2_Error */
if (!class_exists('Eden_Oauth2_Error')) {

    class Eden_Oauth2_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Oauth2_Client */
if (!class_exists('Eden_Oauth2_Client')) {

    class Eden_Oauth2_Client extends Eden_Oauth2_Abstract {

        protected $_responseType = self::CODE;
        protected $_accessType = self::ONLINE;
        protected $_approvalPrompt = self::FORCE;
        protected $_grantType = self::AUTHORIZATION;

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function forOffline() {
            $this->_accessType = self::OFFLINE;
            return $this;
        }

        public function forOnline() {
            $this->_accessType = self::ONLINE;
            return $this;
        }

        public function approvalPromptToAuto() {
            $this->_approvalPrompt = self::AUTO;
            return $this;
        }

        public function getLoginUrl($scope = NULL, $display = NULL) {
            Eden_Oauth2_Error::i()->argument(1, 'string', 'array', 'null')->argument(2, 'string', 'array', 'null');
            if (!is_null($scope)) {
                $this->setScope($scope);
            }if (!is_null($display)) {
                $this->setDisplay($display);
            }$query = array(self::RESPONSE_TYPE => $this->_responseType, self::CLIENT_ID => $this->_client, self::REDIRECT_URL => $this->_redirect, self::ACCESS_TYPE => $this->_accessType, self::APROVAL => $this->_approvalPrompt);
            return $this->_getLoginUrl($query);
        }

        public function getAccess($code, $refreshToken = false) {
            Eden_Oauth2_Error::i()->argument(1, 'string')->argument(2, 'bool');
            if ($refreshToken) {
                $query = array(self::CLIENT_ID => $this->_client, self::CLIENT_SECRET => $this->_secret, self::GRANT_TYPE => self::REFRESH_TOKEN);
            } else {
                $query = array(self::CLIENT_ID => $this->_client, self::CLIENT_SECRET => $this->_secret, self::REDIRECT_URL => $this->_redirect, self::GRANT_TYPE => $this->_grantType);
            }return $this->_getAccess($query, $code, $refreshToken);
        }

    }

}
/* Eden_Oauth2_Desktop */
if (!class_exists('Eden_Oauth2_Desktop')) {

    class Eden_Oauth2_Desktop extends Eden_Oauth2_Abstract {

        protected $_responseType = self::CODE;
        protected $_grantType = 'authorization_code';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getLoginUrl($scope = NULL, $display = NULL) {
            Eden_Oauth2_Error::i()->argument(1, 'string', 'array', 'null')->argument(2, 'string', 'array', 'null');
            if (!is_null($scope)) {
                $this->setScope($scope);
            }if (!is_null($display)) {
                $this->setDisplay($display);
            }$query = array(self::RESPONSE_TYPE => $this->_responseType, self::CLIENT_ID => $this->_client, self::REDIRECT_URL => $this->_redirect);
            return $this->_getLoginUrl($query);
        }

        public function getAccess($code) {
            Eden_Oauth2_Error::i()->argument(1, 'string');
            $query = array(self::CLIENT_ID => $this->_client, self::CLIENT_SECRET => $this->_secret, self::REDIRECT_URL => $this->_redirect, self::GRANT_TYPE => $this->_grantType);
            return $this->_getAccess($query, $code);
        }

    }

}
/* Eden_Oauth2 */
if (!class_exists('Eden_Oauth2')) {

    class Eden_Oauth2 extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function client($client, $secret, $redirect, $requestUrl, $accessUrl) {
            Eden_Oauth2_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'url')->argument(4, 'url')->argument(5, 'url');
            return Eden_Oauth2_Client::i($client, $secret, $redirect, $requestUrl, $accessUrl);
        }

        public function desktop($client, $secret, $redirect, $requestUrl, $accessUrl) {
            Eden_Oauth2_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'url')->argument(4, 'url')->argument(5, 'url');
            return Eden_Oauth2_Desktop::i($client, $secret, $redirect, $requestUrl, $accessUrl);
        }

    }

}
/* Eden_Cache */
if (!class_exists('Eden_Cache')) {

    class Eden_Cache extends \Eden {

        protected $_key = NULL;
        protected $_path = NULL;
        protected $_cache = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($root, $key = 'key.php') {
            Eden_Cache_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->setKey($key)->setRoot($root)->build();
        }

        public function build() {
            try {
                $this->_cache = Eden_File::i($this->_path . '/' . $this->_key)->getData();
            } catch (Eden_Path_Error $e) {
                $this->_cache = array();
            }return $this;
        }

        public function get($key, $default = NULL) {
            Eden_Cache_Error::i()->argument(1, 'string');
            if ($this->keyExists($key)) {
                return Eden_File::i($this->_cache[$key])->getData();
            }return $default;
        }

        public function getCreated($key) {
            Eden_Cache_Error::i()->argument(1, 'string');
            if ($this->keyExists($key)) {
                return Eden_File::i($this->_cache[$key])->getTime();
            }return 0;
        }

        public function getKeys() {
            return array_keys($this->_cache);
        }

        public function keyExists($key) {
            Eden_Cache_Error::i()->argument(1, 'string');
            return isset($this->_cache[$key]) && file_exists($this->_cache[$key]);
        }

        public function remove($key) {
            Eden_Cache_Error::i()->argument(1, 'string');
            if (isset($this->_cache[$key])) {
                unset($this->_cache[$key]);
            }Eden_File::i($this->_path . '/' . $this->_key)->setData($this->_cache);
            return $this;
        }

        public function set($key, $path, $data) {
            Eden_Cache_Error::i()->argument(1, 'string')->argument(2, 'string');
            $path = $this->_path . Eden_Path::i($path);
            Eden_File::i($path)->setData($data);
            $this->_cache[$key] = $path;
            Eden_File::i($this->_path . '/' . $this->_key)->setData($this->_cache);
            return $this;
        }

        public function setKey($key) {
            Eden_Cache_Error::i()->argument(1, 'string');
            $this->_key = $key;
            return $this;
        }

        public function setRoot($root) {
            Eden_Cache_Error::i()->argument(1, 'string');
            $this->_path = (string) Eden_Path::i($root)->absolute();
            return $this;
        }

    }

    class Eden_Cache_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Apc */
if (!class_exists('Eden_Apc')) {

    class Eden_Apc extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function __construct() {
            if (!function_exists('apc_cache_info')) {
                Eden_Apc_Error::i(Eden_Apc_Error::NOT_INSTALLED)->trigger();
            }
        }

        public function clear() {
            apc_clear_cache();
            return $this;
        }

        public function get($key) {
            Eden_Memcache_Error::i()->argument(1, 'string', 'array');
            return apc_fetch($key);
        }

        public function remove($key) {
            Eden_Memcache_Error::i()->argument(1, 'string', 'array');
            apc_delete($key);
            return $this;
        }

        public function set($key, $data, $expire = NULL) {
            Eden_Apc_Error::i()->argument(1, 'string')->argument(3, 'int', 'null');
            apc_store($key, $data, $expire);
            return $this;
        }

    }

    class Eden_Apc_Error extends Eden_Error {

        const NOT_INSTALLED = 'APC is not installed.';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Memcache */
if (!class_exists('Eden_Memcache')) {

    class Eden_Memcache extends \Eden {

        protected $_memcache = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($host = 'localhost', $port = 11211, $timeout = 1) {
            $error = Eden_Memcache_Error::i()->argument(1, 'string')->argument(2, 'int')->argument(3, 'int');
            if (!class_exists('Memcached')) {
                $error->setMessage(Eden_Memcache_Error::NOT_INSTALLED)->trigger();
            }try {
                $this->_memcache = new Memcached;
            } catch (Exception $e) {
                $error->setMessage(Eden_Memcache_Error::NOT_INSTALLED)->trigger();
            }$this->_memcache->connect($host, $port, $timeout);
            return $this;
        }

        public function __destruct() {
            if (!is_null($this->_memcache)) {
                $this->_memcache->close();
                $this->_memcache = NULL;
            }
        }

        public function addServer($host = 'localhost', $port = 11211, $persistent = true, $weight = NULL, $timeout = 1) {
            Eden_Memcache_Error::i()->argument(1, 'string')->argument(2, 'int')->argument(3, 'bool')->argument(4, 'int', 'null')->argument(5, 'int');
            $this->_memcache->addServer($host, $port, $persistent, $weight, $timeout);
            return $this;
        }

        public function clear() {
            $this->_memcache->flush();
            return $this;
        }

        public function get($key, $flag = NULL) {
            Eden_Memcache_Error::i()->argument(1, 'string', 'array')->argument(2, 'int', 'null');
            return $this->_memcache->get($key, $flag);
        }

        public function remove($key) {
            Eden_Memcache_Error::i()->argument(1, 'string', 'array');
            $this->_memcache->delete($key);
            return $this;
        }

        public function set($key, $data, $flag = NULL, $expire = NULL) {
            Eden_Memcache_Error::i()->argument(1, 'string')->argument(3, 'int', 'null')->argument(4, 'int', 'null');
            $this->_memcache->set($key, $data, $flag, $expire);
            return $this;
        }

    }

    class Eden_Memcache_Error extends Eden_Error {

        const NOT_INSTALLED = 'Memcache is not installed.';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Mail */
if (!class_exists('Eden_Mail')) {

    class Eden_Mail extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function imap($host, $user, $pass, $port = NULL, $ssl = false, $tls = false) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'int', 'null')->argument(5, 'bool')->argument(6, 'bool');
            return Eden_Mail_Imap::i($host, $user, $pass, $port, $ssl, $tls);
        }

        public function pop3($host, $user, $pass, $port = NULL, $ssl = false, $tls = false) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'int', 'null')->argument(5, 'bool')->argument(6, 'bool');
            return Eden_Mail_Pop3::i($host, $user, $pass, $port, $ssl, $tls);
        }

        public function smtp($host, $user, $pass, $port = NULL, $ssl = false, $tls = false) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'int', 'null')->argument(5, 'bool')->argument(6, 'bool');
            return Eden_Mail_Smtp::i($host, $user, $pass, $port, $ssl, $tls);
        }

    }

}
/* Eden_Mail_Error */
if (!class_exists('Eden_Mail_Error')) {

    class Eden_Mail_Error extends Eden_Error {

        const SERVER_ERROR = 'Problem connecting to %s.Check server,port or ssl settings for your email server.';
        const LOGIN_ERROR = 'Your email provider has rejected your login information.Verify your email and/or password is correct.';
        const TLS_ERROR = 'Problem connecting to %s with TLS on.';
        const SMTP_ADD_EMAIL = 'Adding %s to email failed.';
        const SMTP_DATA = 'Server did not allow data to be added.';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Mail_Imap */
if (!class_exists('Eden_Mail_Imap')) {

    class Eden_Mail_Imap extends \Eden {

        const TIMEOUT = 30;
        const NO_SUBJECT = '(no subject)';

        protected $_host = NULL;
        protected $_port = NULL;
        protected $_ssl = false;
        protected $_tls = false;
        protected $_username = NULL;
        protected $_password = NULL;
        protected $_tag = 0;
        protected $_total = 0;
        protected $_buffer = NULL;
        protected $_socket = NULL;
        protected $_mailbox = NULL;
        protected $_mailboxes = array();
        private $_debugging = false;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($host, $user, $pass, $port = NULL, $ssl = false, $tls = false) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'int', 'null')->argument(5, 'bool')->argument(6, 'bool');
            if (is_null($port)) {
                $port = $ssl ? 993 : 143;
            }$this->_host = $host;
            $this->_username = $user;
            $this->_password = $pass;
            $this->_port = $port;
            $this->_ssl = $ssl;
            $this->_tls = $tls;
        }

        public function connect($timeout = self::TIMEOUT, $test = false) {
            Eden_Mail_Error::i()->argument(1, 'int')->argument(2, 'bool');
            if ($this->_socket) {
                return $this;
            }$host = $this->_host;
            if ($this->_ssl) {
                $host = 'ssl://' . $host;
            }$errno = 0;
            $errstr = '';
            $this->_socket = @fsockopen($host, $this->_port, $errno, $errstr, $timeout);
            if (!$this->_socket) {
                Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SERVER_ERROR)->addVariable($host . ':' . $this->_port)->trigger();
            }if (strpos($this->_getLine(), '* OK') === false) {
                $this->disconnect();
                Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SERVER_ERROR)->addVariable($host . ':' . $this->_port)->trigger();
            }if ($this->_tls) {
                $this->_send('STARTTLS');
                if (!stream_socket_enable_crypto($this->_socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    $this->disconnect();
                    Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::TLS_ERROR)->addVariable($host . ':' . $this->_port)->trigger();
                }
            }if ($test) {
                fclose($this->_socket);
                $this->_socket = NULL;
                return $this;
            }$result = $this->_call('LOGIN', $this->_escape($this->_username, $this->_password));
            if (strpos(implode(' ', $result), 'OK') === false) {
                $this->disconnect();
                Eden_Mail_Error::i(Eden_Mail_Error::LOGIN_ERROR)->trigger();
            }return $this;
        }

        public function disconnect() {
            if ($this->_socket) {
                $this->_send('LOGOUT');
                fclose($this->_socket);
                $this->_socket = NULL;
            }return $this;
        }

        public function getActiveMailbox() {
            return $this->_mailbox;
        }

        public function getEmails($start = 0, $range = 10) {
            Eden_Mail_Error::i()->argument(1, 'int', 'array')->argument(2, 'int');
            if (!$this->_socket) {
                $this->connect();
            }if ($this->_total == 0) {
                return array();
            }if (is_array($start)) {
                $set = implode(',', $start);
            } else {
                $range = $range > 0 ? $range : 1;
                $start = $start >= 0 ? $start : 0;
                $max = $this->_total - $start;
                if ($max < 1) {
                    $max = $this->_total;
                }$min = $max - $range + 1;
                if ($min < 1) {
                    $min = 1;
                }$set = $min . ':' . $max;
                if ($min == $max) {
                    $set = $min;
                }
            }$items = array('UID', 'FLAGS', 'BODY[HEADER]');
            $emails = $this->_getEmailResponse('FETCH', array($set, $this->_getList($items)));
            $emails = array_reverse($emails);
            return $emails;
        }

        public function getEmailTotal() {
            return $this->_total;
        }

        public function getMailboxes() {
            if (!$this->_socket) {
                $this->connect();
            }$response = $this->_call('LIST', $this->_escape('', '*'));
            $mailboxes = array();
            foreach ($response as $line) {
                if (strpos($line, 'Noselect') !== false || strpos($line, 'LIST') == false) {
                    continue;
                }$line = explode('"', $line);
                if (strpos(trim($line[0]), '*') !== 0) {
                    continue;
                }$mailboxes[] = $line[count($line) - 2];
            }return $mailboxes;
        }

        public function getUniqueEmails($uid, $body = false) {
            Eden_Mail_Error::i()->argument(1, 'int', 'string', 'array')->argument(2, 'bool');
            if (!$this->_socket) {
                $this->connect();
            }if ($this->_total == 0) {
                return array();
            }if (is_array($uid)) {
                $uid = implode(',', $uid);
            }$items = array('UID', 'FLAGS', 'BODY[HEADER]');
            if ($body) {
                $items = array('UID', 'FLAGS', 'BODY[]');
            }$first = is_numeric($uid) ? true : false;
            return $this->_getEmailResponse('UID FETCH', array($uid, $this->_getList($items)), $first);
        }

        public function move($uid, $mailbox) {
            Eden_Mail_Error::i()->argument(1, 'int', 'string')->argument(2, 'string');
            if (!$this->_socket) {
                $this->connect();
            }if (!is_array($uid)) {
                $uid = array($uid);
            }$this->_call('UID COPY ' . implode(',', $uid) . ' ' . $mailbox);
            return $this->remove($uid);
        }

        public function remove($uid) {
            Eden_Mail_Error::i()->argument(1, 'int', 'string');
            if (!$this->_socket) {
                $this->connect();
            }if (!is_array($uid)) {
                $uid = array($uid);
            }$this->_call('UID STORE ' . implode(',', $uid) . ' FLAGS.SILENT \Deleted');
            return $this;
        }

        public function search(array $filter, $start = 0, $range = 10, $or = false, $body = false) {
            Eden_Mail_Error::i()->argument(2, 'int')->argument(3, 'int')->argument(4, 'bool')->argument(5, 'bool');
            if (!$this->_socket) {
                $this->connect();
            }$search = $not = array();
            foreach ($filter as $where) {
                if (is_string($where)) {
                    $search[] = $where;
                    continue;
                }if ($where[0] == 'NOT') {
                    $not = $where[1];
                    continue;
                }$item = $where[0] . ' "' . $where[1] . '"';
                if (isset($where[2])) {
                    $item.=' "' . $where[2] . '"';
                }$search[] = $item;
            }if ($or && count($search) > 1) {
                $query = NULL;
                while ($item = array_pop($search)) {
                    if (is_null($query)) {
                        $query = $item;
                    } else if (strpos($query, 'OR') !== 0) {
                        $query = 'OR (' . $query . ') (' . $item . ')';
                    } else {
                        $query = 'OR (' . $item . ') (' . $query . ')';
                    }
                }$search = $query;
            } else {
                $search = implode(' ', $search);
            }$response = $this->_call('UID SEARCH ' . $search);
            $result = array_pop($response);
            if (strpos($result, 'OK') !== false) {
                $uids = explode(' ', $response[0]);
                array_shift($uids);
                array_shift($uids);
                foreach ($uids as $i => $uid) {
                    if (in_array($uid, $not)) {
                        unset($uids[$i]);
                    }
                }if (empty($uids)) {
                    return array();
                }$uids = array_reverse($uids);
                $count = 0;
                foreach ($uids as $i => $id) {
                    if ($i < $start) {
                        unset($uids[$i]);
                        continue;
                    }$count++;
                    if ($range != 0 && $count > $range) {
                        unset($uids[$i]);
                        continue;
                    }
                }return $this->getUniqueEmails($uids, $body);
            }return array();
        }

        public function searchTotal(array $filter, $or = false) {
            Eden_Mail_Error::i()->argument(2, 'bool');
            if (!$this->_socket) {
                $this->connect();
            }$search = array();
            foreach ($filter as $where) {
                $item = $where[0] . ' "' . $where[1] . '"';
                if (isset($where[2])) {
                    $item.=' "' . $where[2] . '"';
                }$search[] = $item;
            }if ($or) {
                $search = 'OR (' . implode(') (', $search) . ')';
            } else {
                $search = implode(' ', $search);
            }$response = $this->_call('UID SEARCH ' . $search);
            $result = array_pop($response);
            if (strpos($result, 'OK') !== false) {
                $uids = explode(' ', $response[0]);
                array_shift($uids);
                array_shift($uids);
                return count($uids);
            }return 0;
        }

        public function setActiveMailbox($mailbox) {
            Eden_Mail_Error::i()->argument(1, 'string');
            if (!$this->_socket) {
                $this->connect();
            }$response = $this->_call('SELECT', $this->_escape($mailbox));
            $result = array_pop($response);
            foreach ($response as $line) {
                if (strpos($line, 'EXISTS') !== false) {
                    list($star, $this->_total, $type) = explode(' ', $line, 3);
                    break;
                }
            }if (strpos($result, 'OK') !== false) {
                $this->_mailbox = $mailbox;
                return $this;
            }return false;
        }

        protected function _call($command, $parameters = array()) {
            if (!$this->_send($command, $parameters)) {
                return false;
            }return $this->_receive($this->_tag);
        }

        protected function _getLine() {
            $line = fgets($this->_socket);
            if ($line === false) {
                $this->disconnect();
            }$this->_debug('Receiving: ' . $line);
            return $line;
        }

        protected function _receive($sentTag) {
            $this->_buffer = array();
            $start = time();
            while (time() < ($start + self::TIMEOUT)) {
                list($receivedTag, $line) = explode(' ', $this->_getLine(), 2);
                $this->_buffer[] = trim($receivedTag . ' ' . $line);
                if ($receivedTag == 'TAG' . $sentTag) {
                    return $this->_buffer;
                }
            }return NULL;
        }

        protected function _send($command, $parameters = array()) {
            $this->_tag++;
            $line = 'TAG' . $this->_tag . ' ' . $command;
            if (!is_array($parameters)) {
                $parameters = array($parameters);
            }foreach ($parameters as $parameter) {
                if (is_array($parameter)) {
                    if (fputs($this->_socket, $line . ' ' . $parameter[0] . "\r\n") === false) {
                        return false;
                    }if (strpos($this->_getLine(), '+ ') === false) {
                        return false;
                    }$line = $parameter[1];
                } else {
                    $line.=' ' . $parameter;
                }
            }$this->_debug('Sending: ' . $line);
            return fputs($this->_socket, $line . "\r\n");
        }

        private function _debug($string) {
            if ($this->_debugging) {
                $string = htmlspecialchars($string);
                echo '<pre>' . $string . '</pre>' . "\n";
            }return $this;
        }

        private function _escape($string) {
            if (func_num_args() < 2) {
                if (strpos($string, "\n") !== false) {
                    return array('{' . strlen($string) . '}', $string);
                } else {
                    return '"' . str_replace(array('\\', '"'), array('\\\\', '\\"'), $string) . '"';
                }
            }$result = array();
            foreach (func_get_args() as $string) {
                $result[] = $this->_escape($string);
            }return $result;
        }

        private function _getEmailFormat($email, $uniqueId = NULL, array $flags = array()) {
            if (is_array($email)) {
                $email = implode("\n", $email);
            }$parts = preg_split("/\n\s*\n/", $email, 2);
            $head = $parts[0];
            $body = NULL;
            if (isset($parts[1]) && trim($parts[1]) != ')') {
                $body = $parts[1];
            }$lines = explode("\n", $head);
            $head = array();
            foreach ($lines as $line) {
                if (trim($line) && preg_match("/^\s+/", $line)) {
                    $head[count($head) - 1].=' ' . trim($line);
                    continue;
                }$head[] = trim($line);
            }$head = implode("\n", $head);
            $recipientsTo = $recipientsCc = $recipientsBcc = $sender = array();
            $headers1 = imap_rfc822_parse_headers($head);
            $headers2 = $this->_getHeaders($head);
            $sender['name'] = NULL;
            if (isset($headers1->from[0]->personal)) {
                $sender['name'] = $headers1->from[0]->personal;
                if (preg_match("/^\=\?[a-zA-Z]+\-[0-9]+.*\?/", strtolower($sender['name']))) {
                    $sender['name'] = str_replace('_', ' ', mb_decode_mimeheader($sender['name']));
                }
            }$sender['email'] = $headers1->from[0]->mailbox . '@' . $headers1->from[0]->host;
            if (isset($headers1->to)) {
                foreach ($headers1->to as $to) {
                    if (!isset($to->mailbox, $to->host)) {
                        continue;
                    }$recipient = array('name' => NULL);
                    if (isset($to->personal)) {
                        $recipient['name'] = $to->personal;
                        if (preg_match("/^\=\?[a-zA-Z]+\-[0-9]+.*\?/", strtolower($recipient['name']))) {
                            $recipient['name'] = str_replace('_', ' ', mb_decode_mimeheader($recipient['name']));
                        }
                    }$recipient['email'] = $to->mailbox . '@' . $to->host;
                    $recipientsTo[] = $recipient;
                }
            }if (isset($headers1->cc)) {
                foreach ($headers1->cc as $cc) {
                    $recipient = array('name' => NULL);
                    if (isset($cc->personal)) {
                        $recipient['name'] = $cc->personal;
                        if (preg_match("/^\=\?[a-zA-Z]+\-[0-9]+.*\?/", strtolower($recipient['name']))) {
                            $recipient['name'] = str_replace('_', ' ', mb_decode_mimeheader($recipient['name']));
                        }
                    }$recipient['email'] = $cc->mailbox . '@' . $cc->host;
                    $recipientsCc[] = $recipient;
                }
            }if (isset($headers1->bcc)) {
                foreach ($headers1->bcc as $bcc) {
                    $recipient = array('name' => NULL);
                    if (isset($bcc->personal)) {
                        $recipient['name'] = $bcc->personal;
                        if (preg_match("/^\=\?[a-zA-Z]+\-[0-9]+.*\?/", strtolower($recipient['name']))) {
                            $recipient['name'] = str_replace('_', ' ', mb_decode_mimeheader($recipient['name']));
                        }
                    }$recipient['email'] = $bcc->mailbox . '@' . $bcc->host;
                    $recipientsBcc[] = $recipient;
                }
            }if (!isset($headers1->subject) || strlen(trim($headers1->subject)) === 0) {
                $headers1->subject = self::NO_SUBJECT;
            }$headers1->subject = str_replace(array('<', '>'), '', trim($headers1->subject));
            if (preg_match("/^\=\?[a-zA-Z]+\-[0-9]+.*\?/", strtolower($headers1->subject))) {
                $headers1->subject = str_replace('_', ' ', mb_decode_mimeheader($headers1->subject));
            }$topic = isset($headers2['thread-topic']) ? $headers2['thread-topic'] : $headers1->subject;
            $parent = isset($headers2['in-reply-to']) ? str_replace('"', '', $headers2['in-reply-to']) : NULL;
            $date = isset($headers1->date) ? strtotime($headers1->date) : NULL;
            if (isset($headers2['message-id'])) {
                $messageId = str_replace('"', '', $headers2['message-id']);
            } else {
                $messageId = '<eden-no-id-' . md5(uniqid()) . '>';
            }$attachment = isset($headers2['content-type']) && strpos($headers2['content-type'], 'multipart/mixed') === 0;
            $format = array('id' => $messageId, 'parent' => $parent, 'topic' => $topic, 'mailbox' => $this->_mailbox, 'uid' => $uniqueId, 'date' => $date, 'subject' => str_replace('’', '\'', $headers1->subject), 'from' => $sender, 'flags' => $flags, 'to' => $recipientsTo, 'cc' => $recipientsCc, 'bcc' => $recipientsBcc, 'attachment' => $attachment);
            if (trim($body) && $body != ')') {
                $parts = $this->_getParts($email);
                if (empty($parts)) {
                    $parts = array('text/plain' => $body);
                }$body = $parts;
                $attachment = array();
                if (isset($body['attachment'])) {
                    $attachment = $body['attachment'];
                    unset($body['attachment']);
                }$format['body'] = $body;
                $format['attachment'] = $attachment;
            }return $format;
        }

        private function _getEmailResponse($command, $parameters = array(), $first = false) {
            if (!$this->_send($command, $parameters)) {
                return false;
            }$messageId = $uniqueId = $count = 0;
            $emails = $email = array();
            $start = time();
            while (time() < ($start + self::TIMEOUT)) {
                $line = str_replace("\n", '', $this->_getLine());
                if (strpos($line, 'FETCH') !== false && strpos($line, 'TAG' . $this->_tag) === false) {
                    if (!empty($email)) {
                        $emails[$uniqueId] = $this->_getEmailFormat($email, $uniqueId, $flags);
                        if ($first) {
                            return $emails[$uniqueId];
                        }$email = array();
                    }if (strpos($line, 'OK') !== false) {
                        continue;
                    }$flags = array();
                    if (strpos($line, '\Answered') !== false) {
                        $flags[] = 'answered';
                    }if (strpos($line, '\Flagged') !== false) {
                        $flags[] = 'flagged';
                    }if (strpos($line, '\Deleted') !== false) {
                        $flags[] = 'deleted';
                    }if (strpos($line, '\Seen') !== false) {
                        $flags[] = 'seen';
                    }if (strpos($line, '\Draft') !== false) {
                        $flags[] = 'draft';
                    }$findUid = explode(' ', $line);
                    foreach ($findUid as $i => $uid) {
                        if (is_numeric($uid)) {
                            $uniqueId = $uid;
                        }if (strpos(strtolower($uid), 'uid') !== false) {
                            $uniqueId = $findUid[$i + 1];
                            break;
                        }
                    }continue;
                }if (strpos($line, 'TAG' . $this->_tag) !== false) {
                    if (!empty($email) && strpos(trim($email[count($email) - 1]), ')') === 0) {
                        array_pop($email);
                    }if (!empty($email)) {
                        $emails[$uniqueId] = $this->_getEmailFormat($email, $uniqueId, $flags);
                        if ($first) {
                            return $emails[$uniqueId];
                        }
                    }break;
                }$email[] = $line;
            }return $emails;
        }

        private function _getHeaders($rawData) {
            if (is_string($rawData)) {
                $rawData = explode("\n", $rawData);
            }$key = NULL;
            $headers = array();
            foreach ($rawData as $line) {
                $line = trim($line);
                if (preg_match("/^([a-zA-Z0-9-]+):/i", $line, $matches)) {
                    $key = strtolower($matches[1]);
                    if (isset($headers[$key])) {
                        if (!is_array($headers[$key])) {
                            $headers[$key] = array($headers[$key]);
                        }$headers[$key][] = trim(str_replace($matches[0], '', $line));
                        continue;
                    }$headers[$key] = trim(str_replace($matches[0], '', $line));
                    continue;
                }if (!is_null($key) && isset($headers[$key])) {
                    if (is_array($headers[$key])) {
                        $headers[$key][count($headers[$key]) - 1].=' ' . $line;
                        continue;
                    }$headers[$key].=' ' . $line;
                }
            }return $headers;
        }

        private function _getList($array) {
            $list = array();
            foreach ($array as $key => $value) {
                $list[] = !is_array($value) ? $value : $this->_getList($v);
            }return '(' . implode(' ', $list) . ')';
        }

        private function _getParts($content, array $parts = array()) {
            list($head, $body) = preg_split("/\n\s*\n/", $content, 2);
            $head = $this->_getHeaders($head);
            if (!isset($head['content-type'])) {
                return $parts;
            }if (is_array($head['content-type'])) {
                $type = array($head['content-type'][1]);
                if (strpos($type[0], ';') !== false) {
                    $type = explode(';', $type[0], 2);
                }
            } else {
                $type = explode(';', $head['content-type'], 2);
            }$extra = array();
            if (count($type) == 2) {
                $extra = explode(';', str_replace(array('"', "'"), '', trim($type[1])));
            }$type = trim($type[0]);
            foreach ($extra as $i => $attr) {
                $attr = explode('=', $attr, 2);
                if (count($attr) > 1) {
                    list($key, $value) = $attr;
                    $extra[$key] = $value;
                }unset($extra[$i]);
            }if (isset($extra['boundary'])) {
                $sections = explode('--' . str_replace(array('"', "'"), '', $extra['boundary']), $body);
                array_pop($sections);
                array_shift($sections);
                foreach ($sections as $section) {
                    $parts = $this->_getParts($section, $parts);
                }
            } else {
                if (isset($head['content-transfer-encoding'])) {
                    switch (strtolower($head['content-transfer-encoding'])) {
                        case 'binary': $body = imap_binary($body);
                        case 'base64': $body = base64_decode($body);
                            break;
                        case 'quoted-printable': $body = quoted_printable_decode($body);
                            break;
                        case '7bit': $body = mb_convert_encoding($body, 'UTF-8', 'ISO-2022-JP');
                            break;
                        default: $body = str_replace(array("\n", ' '), '', $body);
                            break;
                    }
                }if (isset($extra['name'])) {
                    $parts['attachment'][$extra['name']][$type] = $body;
                } else {
                    $parts[$type] = $body;
                }
            }return $parts;
        }

    }

}
/* Eden_Mail_Pop3 */
if (!class_exists('Eden_Mail_Pop3')) {

    class Eden_Mail_Pop3 extends \Eden {

        const TIMEOUT = 30;

        protected $_host = NULL;
        protected $_port = NULL;
        protected $_ssl = false;
        protected $_tls = false;
        protected $_username = NULL;
        protected $_password = NULL;
        protected $_timestamp = NULL;
        protected $_socket = NULL;
        private $_debugging = false;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($host, $user, $pass, $port = NULL, $ssl = false, $tls = false) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'int', 'null')->argument(5, 'bool')->argument(6, 'bool');
            if (is_null($port)) {
                $port = $ssl ? 995 : 110;
            }$this->_host = $host;
            $this->_username = $user;
            $this->_password = $pass;
            $this->_port = $port;
            $this->_ssl = $ssl;
            $this->_tls = $tls;
            $this->_connect();
        }

        public function connect($test = false) {
            Eden_Mail_Error::i()->argument(1, 'bool');
            if ($this->_loggedin) {
                return $this;
            }$host = $this->_host;
            if ($this->_ssl) {
                $host = 'ssl://' . $host;
            }$errno = 0;
            $errstr = '';
            $this->_socket = fsockopen($host, $this->_port, $errno, $errstr, self::TIMEOUT);
            if (!$this->_socket) {
                Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SERVER_ERROR)->addVariable($host . ':' . $this->_port)->trigger();
            }$welcome = $this->_receive();
            strtok($welcome, '<');
            $this->_timestamp = strtok('>');
            if (!strpos($this->_timestamp, '@')) {
                $this->_timestamp = null;
            } else {
                $this->_timestamp = '<' . $this->_timestamp . '>';
            }if ($this->_tls) {
                $this->_call('STLS');
                if (!stream_socket_enable_crypto($this->_socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    $this->disconnect();
                    Eden_Mail_Error::i()->setMessage(Eden_Mail_Exception::TLS_ERROR)->addVariable($host . ':' . $this->_port)->trigger();
                }
            }if ($this->_timestamp) {
                try {
                    $this->_call('APOP ' . $this->_username . ' ' . md5($this->_timestamp . $this->_password));
                    return;
                } catch (Exception $e) {
                    
                }
            }$this->_call('USER ' . $this->_username);
            $this->_call('PASS ' . $this->_password);
            return $this;
        }

        public function disconnect() {
            if (!$this->_socket) {
                return;
            }try {
                $this->request('QUIT');
            } catch (Exception $e) {
                
            }fclose($this->_socket);
            $this->_socket = NULL;
        }

        public function getEmails($start = 0, $range = 10) {
            Eden_Mail_Error::i()->argument(1, 'int')->argument(2, 'int');
            $total = $this->getEmailTotal();
            $total = $total['messages'];
            if ($total == 0) {
                return array();
            }if (!is_array($start)) {
                $range = $range > 0 ? $range : 1;
                $start = $start >= 0 ? $start : 0;
                $max = $total - $start;
                if ($max < 1) {
                    $max = $total;
                }$min = $max - $range + 1;
                if ($min < 1) {
                    $min = 1;
                }$set = $min . ':' . $max;
                if ($min == $max) {
                    $set = $min;
                }
            }$emails = array();
            for ($i = $min; $i <= $max; $i++) {
                $emails[] = $this->_call('RETR ' . $i, true);
            }return $emails;
        }

        public function getEmailTotal() {
            list($messages, $octets) = explode(' ', $this->_call('STAT'));
            return array('messages' => $messages, 'octets' => $octets);
        }

        public function remove($msgno) {
            Eden_Mail_Error::i()->argument(1, 'int', 'string');
            $this->_call("DELE $msgno");
            if (!$this->_loggedin || !$this->_socket) {
                return false;
            }if (!is_array($msgno)) {
                $msgno = array($msgno);
            }foreach ($msgno as $number) {
                $this->_call('DELE ' . $number);
            }return $this;
        }

        protected function _call($command, $multiline = false) {
            if (!$this->_send($command)) {
                return false;
            }return $this->_receive($multiline);
        }

        protected function _receive($multiline = false) {
            $result = @fgets($this->_socket);
            $status = $result = trim($result);
            $message = '';
            if (strpos($result, ' ')) {
                list($status, $message) = explode(' ', $result, 2);
            }if ($status != '+OK') {
                return false;
            }if ($multiline) {
                $message = '';
                $line = fgets($this->_socket);
                while ($line && rtrim($line, "\r\n") != '.') {
                    if ($line[0] == '.') {
                        $line = substr($line, 1);
                    }$this->_debug('Receiving: ' . $line);
                    $message.=$line;
                    $line = fgets($this->_socket);
                };
            }return $message;
        }

        protected function _send($command) {
            $this->_debug('Sending: ' . $command);
            return fputs($this->_socket, $command . "\r\n");
        }

        private function _debug($string) {
            if ($this->_debugging) {
                $string = htmlspecialchars($string);
                echo '<pre>' . $string . '</pre>' . "\n";
            }return $this;
        }

    }

}
/* Eden_Mail_Smtp */
if (!class_exists('Eden_Mail_Smtp')) {

    class Eden_Mail_Smtp extends \Eden {

        const TIMEOUT = 30;

        protected $_host = NULL;
        protected $_port = NULL;
        protected $_ssl = false;
        protected $_tls = false;
        protected $_username = NULL;
        protected $_password = NULL;
        protected $_socket = NULL;
        protected $_boundary = array();
        protected $_subject = NULL;
        protected $_body = array();
        protected $_to = array();
        protected $_cc = array();
        protected $_bcc = array();
        protected $_attachments = array();
        private $_debugging = false;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($host, $user, $pass, $port = NULL, $ssl = false, $tls = false) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'int', 'null')->argument(5, 'bool')->argument(6, 'bool');
            if (is_null($port)) {
                $port = $ssl ? 465 : 25;
            }$this->_host = $host;
            $this->_username = $user;
            $this->_password = $pass;
            $this->_port = $port;
            $this->_ssl = $ssl;
            $this->_tls = $tls;
            $this->_boundary[] = md5(time() . '1');
            $this->_boundary[] = md5(time() . '2');
        }

        public function addAttachment($filename, $data, $mime = NULL) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string', 'null');
            $this->_attachments[] = array($filename, $data, $mime);
            return $this;
        }

        public function addBCC($email, $name = NULL) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            $this->_bcc[$email] = $name;
            return $this;
        }

        public function addCC($email, $name = NULL) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            $this->_cc[$email] = $name;
            return $this;
        }

        public function addTo($email, $name = NULL) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            $this->_to[$email] = $name;
            return $this;
        }

        public function connect($timeout = self::TIMEOUT, $test = false) {
            Eden_Mail_Error::i()->argument(1, 'int')->argument(2, 'bool');
            $host = $this->_host;
            if ($this->_ssl) {
                $host = 'ssl://' . $host;
            } else {
                $host = 'tcp://' . $host;
            }$errno = 0;
            $errstr = '';
            $this->_socket = @stream_socket_client($host . ':' . $this->_port, $errno, $errstr, $timeout);
            if (!$this->_socket || strlen($errstr) > 0 || $errno > 0) {
                Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SERVER_ERROR)->addVariable($host . ':' . $this->_port)->trigger();
            }$this->_receive();
            if (!$this->_call('EHLO ' . $_SERVER['HTTP_HOST'], 250) && !$this->_call('HELO ' . $_SERVER['HTTP_HOST'], 250)) {
                $this->disconnect();
                Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SERVER_ERROR)->addVariable($host . ':' . $this->_port)->trigger();
            };
            if ($this->_tls && !$this->_call('STARTTLS', 220, 250)) {
                if (!stream_socket_enable_crypto($this->_socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    $this->disconnect();
                    Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::TLS_ERROR)->addVariable($host . ':' . $this->_port)->trigger();
                }if (!$this->_call('EHLO ' . $_SERVER['HTTP_HOST'], 250) && !$this->_call('HELO ' . $_SERVER['HTTP_HOST'], 250)) {
                    $this->disconnect();
                    Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SERVER_ERROR)->addVariable($host . ':' . $this->_port)->trigger();
                }
            }if ($test) {
                $this->disconnect();
                return $this;
            }if (!$this->_call('AUTH LOGIN', 250, 334)) {
                $this->disconnect();
                Eden_Mail_Error::i(Eden_Mail_Error::LOGIN_ERROR)->trigger();
            }if (!$this->_call(base64_encode($this->_username), 334)) {
                $this->disconnect();
                Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::LOGIN_ERROR);
            }if (!$this->_call(base64_encode($this->_password), 235, 334)) {
                $this->disconnect();
                Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::LOGIN_ERROR);
            }return $this;
        }

        public function disconnect() {
            if ($this->_socket) {
                $this->_send('QUIT');
                fclose($this->_socket);
                $this->_socket = NULL;
            }return $this;
        }

        public function reply($messageId, $topic = NULL, array $headers = array()) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            $headers['In-Reply-To'] = $messageId;
            if ($topic) {
                $headers['Thread-Topic'] = $topic;
            }return $this->send($headers);
        }

        public function reset() {
            $this->_subject = NULL;
            $this->_body = array();
            $this->_to = array();
            $this->_cc = array();
            $this->_bcc = array();
            $this->_attachments = array();
            $this->disconnect();
            return $this;
        }

        public function send(array $headers = array()) {
            if (!$this->_socket) {
                $this->connect();
            }$headers = $this->_getHeaders($headers);
            $body = $this->_getBody();
            if (!$this->_call('MAIL FROM:<' . $this->_username . '>', 250, 251)) {
                $this->disconnect();
                Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SMTP_ADD_EMAIL)->addVariable($this->_username)->trigger();
            }foreach ($this->_to as $email => $name) {
                if (!$this->_call('RCPT TO:<' . $email . '>', 250, 251)) {
                    $this->disconnect();
                    Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SMTP_ADD_EMAIL)->addVariable($email)->trigger();
                }
            }foreach ($this->_cc as $email => $name) {
                if (!$this->_call('RCPT TO:<' . $email . '>', 250, 251)) {
                    $this->disconnect();
                    Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SMTP_ADD_EMAIL)->addVariable($email)->trigger();
                }
            }foreach ($this->_bcc as $email => $name) {
                if (!$this->_call('RCPT TO:<' . $email . '>', 250, 251)) {
                    $this->disconnect();
                    Eden_Mail_Error::i()->setMessage(Eden_Mail_Error::SMTP_ADD_EMAIL)->addVariable($email)->trigger();
                }
            }if (!$this->_call('DATA', 354)) {
                $this->disconnect();
                Eden_Mail_Error::i(Eden_Mail_Error::SMTP_DATA)->trigger();
            }foreach ($headers as $name => $value) {
                $this->_send($name . ': ' . $value);
            }foreach ($body as $line) {
                if (strpos($line, '.') === 0) {
                    $line = '.' . $line;
                }$this->_send($line);
            }if (!$this->_call("\r\n.\r\n", 250)) {
                $this->disconnect();
                Eden_Mail_Error::i(Eden_Mail_Error::SMTP_DATA)->trigger();
            }$this->_send('RSET');
            return $headers;
        }

        public function setBody($body, $html = false) {
            Eden_Mail_Error::i()->argument(1, 'string')->argument(2, 'bool');
            if ($html) {
                $this->_body['text/html'] = $body;
                $body = strip_tags($body);
            }$this->_body['text/plain'] = $body;
            return $this;
        }

        public function setSubject($subject) {
            Eden_Mail_Error::i()->argument(1, 'string');
            $this->_subject = $subject;
            return $this;
        }

        protected function _addAttachmentBody(array $body) {
            foreach ($this->_attachments as $attachment) {
                list($name, $data, $mime) = $attachment;
                $mime = $mime ? $mime : Eden_File::i()->getMimeType($name);
                $data = base64_encode($data);
                $count = ceil(strlen($data) / 998);
                $body[] = '--' . $this->_boundary[1];
                $body[] = 'Content-type: ' . $mime . ';name="' . $name . '"';
                $body[] = 'Content-disposition: attachment;filename="' . $name . '"';
                $body[] = 'Content-transfer-encoding: base64';
                $body[] = NULL;
                for ($i = 0; $i < $count; $i++) {
                    $body[] = substr($data, ($i * 998), 998);
                }$body[] = NULL;
                $body[] = NULL;
            }$body[] = '--' . $this->_boundary[1] . '--';
            return $body;
        }

        protected function _call($command, $code = NULL) {
            if (!$this->_send($command)) {
                return false;
            }$receive = $this->_receive();
            $args = func_get_args();
            if (count($args) > 1) {
                for ($i = 1; $i < count($args); $i++) {
                    if (strpos($receive, (string) $args[$i]) === 0) {
                        return true;
                    }
                }return false;
            }return $receive;
        }

        protected function _getAlternativeAttachmentBody() {
            $alternative = $this->_getAlternativeBody();
            $body = array();
            $body[] = 'Content-Type: multipart/mixed;boundary="' . $this->_boundary[1] . '"';
            $body[] = NULL;
            $body[] = '--' . $this->_boundary[1];
            foreach ($alternative as $line) {
                $body[] = $line;
            }return $this->_addAttachmentBody($body);
        }

        protected function _getAlternativeBody() {
            $plain = $this->_getPlainBody();
            $html = $this->_getHtmlBody();
            $body = array();
            $body[] = 'Content-Type: multipart/alternative;boundary="' . $this->_boundary[0] . '"';
            $body[] = NULL;
            $body[] = '--' . $this->_boundary[0];
            foreach ($plain as $line) {
                $body[] = $line;
            }$body[] = '--' . $this->_boundary[0];
            foreach ($html as $line) {
                $body[] = $line;
            }$body[] = '--' . $this->_boundary[0] . '--';
            $body[] = NULL;
            $body[] = NULL;
            return $body;
        }

        protected function _getBody() {
            $type = 'Plain';
            if (count($this->_body) > 1) {
                $type = 'Alternative';
            } else if (isset($this->_body['text/html'])) {
                $type = 'Html';
            }$method = '_get%sBody';
            if (!empty($this->_attachments)) {
                $method = '_get%sAttachmentBody';
            }$method = sprintf($method, $type);
            return $this->$method();
        }

        protected function _getHeaders(array $customHeaders = array()) {
            $timestamp = $this->_getTimestamp();
            $subject = trim($this->_subject);
            $subject = str_replace(array("\n", "\r"), '', $subject);
            $to = $cc = $bcc = array();
            foreach ($this->_to as $email => $name) {
                $to[] = trim($name . ' <' . $email . '>');
            }foreach ($this->_cc as $email => $name) {
                $cc[] = trim($name . ' <' . $email . '>');
            }foreach ($this->_bcc as $email => $name) {
                $bcc[] = trim($name . ' <' . $email . '>');
            }list($account, $suffix) = explode('@', $this->_username);
            $headers = array('Date' => $timestamp, 'Subject' => $subject, 'From' => '<' . $this->_username . '>', 'To' => implode(',', $to));
            if (!empty($cc)) {
                $headers['Cc'] = implode(',', $cc);
            }if (!empty($bcc)) {
                $headers['Bcc'] = implode(',', $bcc);
            }$headers['Message-ID'] = '<' . md5(uniqid(time())) . '.eden@' . $suffix . '>';
            $headers['Thread-Topic'] = $this->_subject;
            $headers['Reply-To'] = '<' . $this->_username . '>';
            foreach ($customHeaders as $key => $value) {
                $headers[$key] = $value;
            }return $headers;
        }

        protected function _getHtmlAttachmentBody() {
            $html = $this->_getHtmlBody();
            $body = array();
            $body[] = 'Content-Type: multipart/mixed;boundary="' . $this->_boundary[1] . '"';
            $body[] = NULL;
            $body[] = '--' . $this->_boundary[1];
            foreach ($html as $line) {
                $body[] = $line;
            }return $this->_addAttachmentBody($body);
        }

        protected function _getHtmlBody() {
            $charset = $this->_isUtf8($this->_body['text/html']) ? 'utf-8' : 'US-ASCII';
            $html = str_replace("\r", '', trim($this->_body['text/html']));
            $encoded = explode("\n", $this->_quotedPrintableEncode($html));
            $body = array();
            $body[] = 'Content-Type: text/html;charset=' . $charset;
            $body[] = 'Content-Transfer-Encoding: quoted-printable' . "\n";
            foreach ($encoded as $line) {
                $body[] = $line;
            }$body[] = NULL;
            $body[] = NULL;
            return $body;
        }

        protected function _getPlainAttachmentBody() {
            $plain = $this->_getPlainBody();
            $body = array();
            $body[] = 'Content-Type: multipart/mixed;boundary="' . $this->_boundary[1] . '"';
            $body[] = NULL;
            $body[] = '--' . $this->_boundary[1];
            foreach ($plain as $line) {
                $body[] = $line;
            }return $this->_addAttachmentBody($body);
        }

        protected function _getPlainBody() {
            $charset = $this->_isUtf8($this->_body['text/plain']) ? 'utf-8' : 'US-ASCII';
            $plane = str_replace("\r", '', trim($this->_body['text/plain']));
            $count = ceil(strlen($plane) / 998);
            $body = array();
            $body[] = 'Content-Type: text/plain;charset=' . $charset;
            $body[] = 'Content-Transfer-Encoding: 7bit';
            $body[] = NULL;
            for ($i = 0; $i < $count; $i++) {
                $body[] = substr($plane, ($i * 998), 998);
            }$body[] = NULL;
            $body[] = NULL;
            return $body;
        }

        protected function _receive() {
            $data = '';
            $now = time();
            while ($str = fgets($this->_socket, 1024)) {
                $data.=$str;
                if (substr($str, 3, 1) == ' ' || time() > ($now + self::TIMEOUT)) {
                    break;
                }
            }$this->_debug('Receiving: ' . $data);
            return $data;
        }

        protected function _send($command) {
            $this->_debug('Sending: ' . $command);
            return fwrite($this->_socket, $command . "\r\n");
        }

        private function _debug($string) {
            if ($this->_debugging) {
                $string = htmlspecialchars($string);
                echo '<pre>' . $string . '</pre>' . "\n";
            }return $this;
        }

        private function _getTimestamp() {
            $zone = date('Z');
            $sign = ($zone < 0) ? '-' : '+';
            $zone = abs($zone);
            $zone = (int) ($zone / 3600) * 100 + ($zone % 3600) / 60;
            return sprintf("%s %s%04d", date('D,j M Y H:i:s'), $sign, $zone);
        }

        private function _isUtf8($string) {
            $regex = array('[\xC2-\xDF][\x80-\xBF]', '\xE0[\xA0-\xBF][\x80-\xBF]', '[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}', '\xED[\x80-\x9F][\x80-\xBF]', '\xF0[\x90-\xBF][\x80-\xBF]{2}', '[\xF1-\xF3][\x80-\xBF]{3}', '\xF4[\x80-\x8F][\x80-\xBF]{2}');
            $count = ceil(strlen($string) / 5000);
            for ($i = 0; $i < $count; $i++) {
                if (preg_match('%(?:' . implode('|', $regex) . ')+%xs', substr($string, ($i * 5000), 5000))) {
                    return false;
                }
            }return true;
        }

        private function _quotedPrintableEncode($input, $line_max = 250) {
            $hex = array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');
            $lines = preg_split("/(?:\r\n|\r|\n)/", $input);
            $linebreak = "=0D=0A=\r\n";
            $line_max = $line_max - strlen($linebreak);
            $escape = "=";
            $output = "";
            $cur_conv_line = "";
            $length = 0;
            $whitespace_pos = 0;
            $addtl_chars = 0;
            for ($j = 0; $j < count($lines); $j++) {
                $line = $lines[$j];
                $linlen = strlen($line);
                for ($i = 0; $i < $linlen; $i++) {
                    $c = substr($line, $i, 1);
                    $dec = ord($c);
                    $length++;
                    if ($dec == 32) {
                        if (($i == ($linlen - 1))) {
                            $c = "=20";
                            $length +=2;
                        }$addtl_chars = 0;
                        $whitespace_pos = $i;
                    } elseif (($dec == 61) || ($dec < 32 ) || ($dec > 126)) {
                        $h2 = floor($dec / 16);
                        $h1 = floor($dec % 16);
                        $c = $escape . $hex["$h2"] . $hex["$h1"];
                        $length +=2;
                        $addtl_chars +=2;
                    }if ($length >= $line_max) {
                        $cur_conv_line.=$c;
                        $whitesp_diff = $i - $whitespace_pos + $addtl_chars;
                        if (($i + $addtl_chars) > $whitesp_diff) {
                            $output.=substr($cur_conv_line, 0, (strlen($cur_conv_line) - $whitesp_diff)) . $linebreak;
                            $i = $i - $whitesp_diff + $addtl_chars;
                        } else {
                            $output.=$cur_conv_line . $linebreak;
                        }$cur_conv_line = "";
                        $length = 0;
                        $whitespace_pos = 0;
                    } else {
                        $cur_conv_line.=$c;
                    }
                }$length = 0;
                $whitespace_pos = 0;
                $output.=$cur_conv_line;
                $cur_conv_line = "";
                if ($j <= count($lines) - 1) {
                    $output.=$linebreak;
                }
            }return trim($output);
        }

    }

}
/* Eden_Sql_Error */
if (!class_exists('Eden_Sql_Error')) {

    class Eden_Sql_Error extends Eden_Error {

        const QUERY_ERROR = '%s Query: %s';
        const TABLE_NOT_SET = 'No default table set or was passed.';
        const DATABASE_NOT_SET = 'No default database set or was passed.';
        const NOT_SUB_MODEL = 'Class %s is not a child of Eden_Model';
        const NOT_SUB_COLLECTION = 'Class %s is not a child of Eden_Collection';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Mysql_Error */
if (!class_exists('Eden_Mysql_Error')) {

    class Eden_Mysql_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Sql_Database */
if (!class_exists('Eden_Sql_Database')) {

    abstract class Eden_Sql_Database extends Eden_Event {

        const QUERY = 'Eden_Sql_Query';
        const FIRST = 'first';
        const LAST = 'last';
        const MODEL = 'Eden_Sql_Model';
        const COLLECTION = 'Eden_Sql_Collection';

        protected $_queries = array();
        protected $_connection = NULL;
        protected $_binds = array();
        protected $_model = self::MODEL;
        protected $_collection = self::COLLECTION;

        abstract public function connect(array $options = array());

        public function bind($value) {
            Eden_Sql_Error::i()->argument(1, 'array', 'string', 'numeric', 'null');
            if (is_array($value)) {
                foreach ($value as $i => $item) {
                    $value[$i] = $this->bind($item);
                }return '(' . implode(",", $value) . ')';
            } else if (is_numeric($value)) {
                return $value;
            }$name = ':bind' . count($this->_binds) . 'bind';
            $this->_binds[$name] = $value;
            return $name;
        }

        public function collection(array $data = array()) {
            $collection = $this->_collection;
            return $this->$collection()->setDatabase($this)->setModel($this->_model)->set($data);
        }

        public function delete($table = NULL) {
            Eden_Sql_Error::i()->argument(1, 'string', 'null');
            return Eden_Sql_Delete::i($table);
        }

        public function deleteRows($table, $filters = NULL) {
            Eden_Sql_Error::i()->argument(1, 'string');
            $query = $this->delete($table);
            if (is_array($filters)) {
                foreach ($filters as $i => $filter) {
                    $format = array_shift($filter);
                    foreach ($filter as $j => $value) {
                        $filter[$j] = $this->bind($value);
                    }$filters[$i] = vsprintf($format, $filter);
                }
            }$query->where($filters);
            $this->query($query, $this->getBinds());
            $this->trigger($table, $filters);
            return $this;
        }

        public function getBinds() {
            return $this->_binds;
        }

        public function getCollection($table, array $joins = array(), $filters = NULL, array $sort = array(), $start = 0, $range = 0, $index = NULL) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(3, 'string', 'array', 'null')->argument(5, 'numeric')->argument(6, 'numeric')->argument(7, 'numeric', 'null');
            $results = $this->getRows($table, $joins, $filters, $sort, $start, $range, $index);
            $collection = $this->collection()->setTable($table)->setModel($this->_model);
            if (is_null($results)) {
                return $collection;
            }if (!is_null($index)) {
                return $this->model($results)->setTable($table);
            }return $collection->set($results);
        }

        public function getConnection() {
            if (!$this->_connection) {
                $this->connect();
            }return $this->_connection;
        }

        public function getLastInsertedId() {
            return $this->getConnection()->lastInsertId();
        }

        public function getModel($table, $name, $value) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string', 'numeric');
            $result = $this->getRow($table, $name, $value);
            $model = $this->model()->setTable($table);
            if (is_null($result)) {
                return $model;
            }return $model->set($result);
        }

        public function getQueries($index = NULL) {
            if (is_null($index)) {
                return $this->_queries;
            }if ($index == self::FIRST) {
                $index = 0;
            }if ($index == self::LAST) {
                $index = count($this->_queries) - 1;
            }if (isset($this->_queries[$index])) {
                return $this->_queries[$index];
            }return NULL;
        }

        public function getRow($table, $name, $value) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string', 'numeric');
            $query = $this->select()->from($table)->where($name . '=' . $this->bind($value))->limit(0, 1);
            $results = $this->query($query, $this->getBinds());
            $this->trigger($table, $name, $value, $results);
            return isset($results[0]) ? $results[0] : NULL;
        }

        public function getRows($table, array $joins = array(), $filters = NULL, array $sort = array(), $start = 0, $range = 0, $index = NULL) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(3, 'string', 'array', 'null')->argument(5, 'numeric')->argument(6, 'numeric')->argument(7, 'numeric', 'null');
            $query = $this->select()->from($table);
            foreach ($joins as $join) {
                if (!is_array($join) || count($join) < 3) {
                    continue;
                }if (count($join) == 3) {
                    $join[] = true;
                }$query->join($join[0], $join[1], $join[2], $join[3]);
            }if (is_array($filters)) {
                foreach ($filters as $i => $filter) {
                    $format = array_shift($filter);
                    foreach ($filter as $j => $value) {
                        $filter[$j] = $this->bind($value);
                    }$filters[$i] = vsprintf($format, $filter);
                }
            }if (!is_null($filters)) {
                $query->where($filters);
            }if (!empty($sort)) {
                foreach ($sort as $key => $value) {
                    if (is_string($key) && trim($key)) {
                        $query->sortBy($key, $value);
                    }
                }
            }if ($range) {
                $query->limit($start, $range);
            }$results = $this->query($query, $this->getBinds());
            if (!is_null($index)) {
                if (empty($results)) {
                    $results = NULL;
                } else {
                    if ($index == self::FIRST) {
                        $index = 0;
                    }if ($index == self::LAST) {
                        $index = count($results) - 1;
                    }if (isset($results[$index])) {
                        $results = $results[$index];
                    } else {
                        $results = NULL;
                    }
                }
            }$this->trigger($table, $joins, $filters, $sort, $start, $range, $index, $results);
            return $results;
        }

        public function getRowsCount($table, array $joins = array(), $filters = NULL) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(3, 'string', 'array', 'null');
            $query = $this->select('COUNT(*) as count')->from($table);
            foreach ($joins as $join) {
                if (!is_array($join) || count($join) < 3) {
                    continue;
                }if (count($join) == 3) {
                    $join[] = true;
                }$query->join($join[0], $join[1], $join[2], $join[3]);
            }if (is_array($filters)) {
                foreach ($filters as $i => $filter) {
                    $format = array_shift($filter);
                    $filter = $this->bind($filter);
                    $filters[$i] = vsprintf($format, $filter);
                }
            }$query->where($filters);
            $results = $this->query($query, $this->getBinds());
            if (isset($results[0]['count'])) {
                $this->trigger($table, $joins, $filters, $results[0]['count']);
                return $results[0]['count'];
            }$this->trigger($table, $joins, $filters, false);
            return false;
        }

        public function insert($table = NULL) {
            Eden_Sql_Error::i()->argument(1, 'string', 'null');
            return Eden_Sql_Insert::i($table);
        }

        public function insertRow($table, array $setting, $bind = true) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(3, 'array', 'bool');
            $query = $this->insert($table);
            foreach ($setting as $key => $value) {
                if (is_null($value) || is_bool($value)) {
                    $query->set($key, $value);
                    continue;
                }if ((is_bool($bind) && $bind) || (is_array($bind) && in_array($key, $bind))) {
                    $value = $this->bind($value);
                }$query->set($key, $value);
            }$this->query($query, $this->getBinds());
            $this->trigger($table, $setting);
            return $this;
        }

        public function insertRows($table, array $settings, $bind = true) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(3, 'array', 'bool');
            $query = $this->insert($table);
            foreach ($settings as $index => $setting) {
                foreach ($setting as $key => $value) {
                    if (is_null($value) || is_bool($value)) {
                        $query->set($key, $value);
                        continue;
                    }if ((is_bool($bind) && $bind) || (is_array($bind) && in_array($key, $bind))) {
                        $value = $this->bind($value);
                    }$query->set($key, $value, $index);
                }
            }$this->query($query, $this->getBinds());
            $this->trigger($table, $settings);
            return $this;
        }

        public function model(array $data = array()) {
            $model = $this->_model;
            return $this->$model($data)->setDatabase($this);
        }

        public function query($query, array $binds = array()) {
            Eden_Sql_Error::i()->argument(1, 'string', self::QUERY);
            $connection = $this->getConnection();
            $query = (string) $query;
            $stmt = $connection->prepare($query);
            foreach ($binds as $key => $value) {
                $stmt->bindValue($key, $value);
            }if (!$stmt->execute()) {
                $error = $stmt->errorInfo();
                foreach ($binds as $key => $value) {
                    $query = str_replace($key, "'$value'", $query);
                }Eden_Sql_Error::i()->setMessage(Eden_Sql_Error::QUERY_ERROR)->addVariable($query)->addVariable($error[2])->trigger();
            }$results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $this->_queries[] = array('query' => $query, 'binds' => $binds, 'results' => $results);
            $this->_binds = array();
            $this->trigger($query, $binds, $results);
            return $results;
        }

        public function search($table = NULL) {
            Eden_Sql_Error::i()->argument(1, 'string', 'null');
            $search = Eden_Sql_Search::i($this)->setCollection($this->_collection)->setModel($this->_model);
            if ($table) {
                $search->setTable($table);
            }return $search;
        }

        public function select($select = '*') {
            Eden_Sql_Error::i()->argument(1, 'string', 'array');
            return Eden_Sql_Select::i($select);
        }

        public function setBinds(array $binds) {
            $this->_binds = $binds;
            return $this;
        }

        public function setCollection($collection) {
            $error = Eden_Sql_Error::i()->argument(1, 'string');
            if (!is_subclass_of($collection, self::COLLECTION)) {
                $error->setMessage(Eden_Sql_Error::NOT_SUB_COLLECTION)->addVariable($collection)->trigger();
            }$this->_collection = $collection;
            return $this;
        }

        public function setModel($model) {
            $error = Eden_Sql_Error::i()->argument(1, 'string');
            if (!is_subclass_of($model, self::MODEL)) {
                $error->setMessage(Eden_Sql_Error::NOT_SUB_MODEL)->addVariable($model)->trigger();
            }$this->_model = $model;
            return $this;
        }

        public function setRow($table, $name, $value, array $setting) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string', 'numeric');
            $row = $this->getRow($table, $name, $value);
            if (!$row) {
                $setting[$name] = $value;
                return $this->insertRow($table, $setting);
            } else {
                return $this->updateRows($table, $setting, array(array($name . '=%s', $value)));
            }
        }

        public function update($table = NULL) {
            Eden_Sql_Error::i()->argument(1, 'string', 'null');
            return Eden_Sql_Update::i($table);
        }

        public function updateRows($table, array $setting, $filters = NULL, $bind = true) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(4, 'array', 'bool');
            $query = $this->update($table);
            foreach ($setting as $key => $value) {
                if (is_null($value) || is_bool($value)) {
                    $query->set($key, $value);
                    continue;
                }if ((is_bool($bind) && $bind) || (is_array($bind) && in_array($key, $bind))) {
                    $value = $this->bind($value);
                }$query->set($key, $value);
            }if (is_array($filters)) {
                foreach ($filters as $i => $filter) {
                    $format = array_shift($filter);
                    foreach ($filter as $j => $value) {
                        $filter[$j] = $this->bind($value);
                    }$filters[$i] = vsprintf($format, $filter);
                }
            }$query->where($filters);
            $this->query($query, $this->getBinds());
            $this->trigger($table, $setting, $filters);
            return $this;
        }

    }

}
/* Eden_Sql_Query */
if (!class_exists('Eden_Sql_Query')) {

    abstract class Eden_Sql_Query extends \Eden {

        public function __toString() {
            return $this->getQuery();
        }

        abstract public function getQuery();
    }

}
/* Eden_Sql_Delete */
if (!class_exists('Eden_Sql_Delete')) {

    class Eden_Sql_Delete extends Eden_Sql_Query {

        protected $_table = NULL;
        protected $_where = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($table = NULL) {
            if (is_string($table)) {
                $this->setTable($table);
            }
        }

        public function getQuery() {
            return 'DELETE FROM ' . $this->_table . ' WHERE ' . implode(' AND ', $this->_where) . ';';
        }

        public function setTable($table) {
            Eden_Sql_Error::i()->argument(1, 'string');
            $this->_table = $table;
            return $this;
        }

        public function where($where) {
            Eden_Sql_Error::i()->argument(1, 'string', 'array');
            if (is_string($where)) {
                $where = array($where);
            }$this->_where = array_merge($this->_where, $where);
            return $this;
        }

    }

}
/* Eden_Sql_Select */
if (!class_exists('Eden_Sql_Select')) {

    class Eden_Sql_Select extends Eden_Sql_Query {

        protected $_select = NULL;
        protected $_from = NULL;
        protected $_joins = NULL;
        protected $_where = array();
        protected $_sortBy = array();
        protected $_group = array();
        protected $_page = NULL;
        protected $_length = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($select = '*') {
            $this->select($select);
        }

        public function from($from) {
            Eden_Sql_Error::i()->argument(1, 'string');
            $this->_from = $from;
            return $this;
        }

        public function getQuery() {
            $joins = empty($this->_joins) ? '' : implode(' ', $this->_joins);
            $where = empty($this->_where) ? '' : 'WHERE ' . implode(' AND ', $this->_where);
            $sort = empty($this->_sortBy) ? '' : 'ORDER BY ' . implode(',', $this->_sortBy);
            $limit = is_null($this->_page) ? '' : 'LIMIT ' . $this->_page . ',' . $this->_length;
            $group = empty($this->_group) ? '' : 'GROUP BY ' . implode(',', $this->_group);
            $query = sprintf('SELECT %s FROM %s %s %s %s %s %s;', $this->_select, $this->_from, $joins, $where, $group, $sort, $limit);
            return str_replace(' ', ' ', $query);
        }

        public function groupBy($group) {
            Eden_Sql_Error::i()->argument(1, 'string', 'array');
            if (is_string($group)) {
                $group = array($group);
            }$this->_group = $group;
            return $this;
        }

        public function innerJoin($table, $where, $using = true) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'bool');
            return $this->join('INNER', $table, $where, $using);
        }

        public function join($type, $table, $where, $using = true) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'bool');
            $linkage = $using ? 'USING (' . $where . ')' : ' ON (' . $where . ')';
            $this->_joins[] = $type . ' JOIN ' . $table . ' ' . $linkage;
            return $this;
        }

        public function leftJoin($table, $where, $using = true) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'bool');
            return $this->join('LEFT', $table, $where, $using);
        }

        public function limit($page, $length) {
            Eden_Sql_Error::i()->argument(1, 'numeric')->argument(2, 'numeric');
            $this->_page = $page;
            $this->_length = $length;
            return $this;
        }

        public function outerJoin($table, $where, $using = true) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'bool');
            return $this->join('OUTER', $table, $where, $using);
        }

        public function rightJoin($table, $where, $using = true) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'bool');
            return $this->join('RIGHT', $table, $where, $using);
        }

        public function select($select = '*') {
            Eden_Sql_Error::i()->argument(1, 'string', 'array');
            if (is_array($select)) {
                $select = implode(',', $select);
            }$this->_select = $select;
            return $this;
        }

        public function sortBy($field, $order = 'ASC') {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_sortBy[] = $field . ' ' . $order;
            return $this;
        }

        public function where($where) {
            Eden_Sql_Error::i()->argument(1, 'string', 'array');
            if (is_string($where)) {
                $where = array($where);
            }$this->_where = array_merge($this->_where, $where);
            return $this;
        }

    }

}
/* Eden_Sql_Update */
if (!class_exists('Eden_Sql_Update')) {

    class Eden_Sql_Update extends Eden_Sql_Delete {

        protected $_set = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getQuery() {
            $set = array();
            foreach ($this->_set as $key => $value) {
                $set[] = "{$key}={$value}";
            }return 'UPDATE ' . $this->_table . ' SET ' . implode(',', $set) . ' WHERE ' . implode(' AND ', $this->_where) . ';';
        }

        public function set($key, $value) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'scalar', 'null');
            if (is_null($value)) {
                $value = 'NULL';
            } else if (is_bool($value)) {
                $value = $value ? 1 : 0;
            }$this->_set[$key] = $value;
            return $this;
        }

    }

}
/* Eden_Sql_Insert */
if (!class_exists('Eden_Sql_Insert')) {

    class Eden_Sql_Insert extends Eden_Sql_Query {

        protected $_setKey = array();
        protected $_setVal = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($table = NULL) {
            if (is_string($table)) {
                $this->setTable($table);
            }
        }

        public function getQuery() {
            $multiValList = array();
            foreach ($this->_setVal as $val) {
                $multiValList[] = '(' . implode(',', $val) . ')';
            }return 'INSERT INTO ' . $this->_table . ' (' . implode(',', $this->_setKey) . ") VALUES " . implode(",\n", $multiValList) . ';';
        }

        public function set($key, $value, $index = 0) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'scalar', 'null');
            if (!in_array($key, $this->_setKey)) {
                $this->_setKey[] = $key;
            }if (is_null($value)) {
                $value = 'NULL';
            } else if (is_bool($value)) {
                $value = $value ? 1 : 0;
            }$this->_setVal[$index][] = $value;
            return $this;
        }

        public function setTable($table) {
            Eden_Sql_Error::i()->argument(1, 'string');
            $this->_table = $table;
            return $this;
        }

    }

}
/* Eden_Sql_Collection */
if (!class_exists('Eden_Sql_Collection')) {

    class Eden_Sql_Collection extends Eden_Collection {

        protected $_model = Eden_Sql_Database::MODEL;
        protected $_database = NULL;
        protected $_table = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function add($row = array()) {
            Eden_Sql_Error::i()->argument(1, 'array', $this->_model);
            if (is_array($row)) {
                $model = $this->_model;
                $row = $this->$model($row);
            }if (!is_null($this->_database)) {
                $row->setDatabase($this->_database);
            }if (!is_null($this->_table)) {
                $row->setTable($this->_table);
            }$this->_list[] = $row;
            return $this;
        }

        public function setDatabase(Eden_Sql_Database $database) {
            $this->_database = $database;
            foreach ($this->_list as $row) {
                if (!is_object($row) || !method_exists($row, __FUNCTION__)) {
                    continue;
                }$row->setDatabase($database);
            }return $this;
        }

        public function setModel($model) {
            $error = Eden_Sql_Error::i()->argument(1, 'string');
            if (!is_subclass_of($model, 'Eden_Model')) {
                $error->setMessage(Eden_Sql_Error::NOT_SUB_MODEL)->addVariable($model)->trigger();
            }$this->_model = $model;
            return $this;
        }

        public function setTable($table) {
            Eden_Sql_Error::i()->argument(1, 'string');
            $this->_table = $table;
            foreach ($this->_list as $row) {
                if (!is_object($row) || !method_exists($row, __FUNCTION__)) {
                    continue;
                }$row->setTable($table);
            }return $this;
        }

    }

}
/* Eden_Sql_Model */
if (!class_exists('Eden_Sql_Model')) {

    class Eden_Sql_Model extends Eden_Model {

        const COLUMNS = 'columns';
        const PRIMARY = 'primary';
        const DATETIME = 'Y-m-d h:i:s';
        const DATE = 'Y-m-d';
        const TIME = 'h:i:s';
        const TIMESTAMP = 'U';

        protected $_table = NULL;
        protected $_database = NULL;
        protected static $_meta = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function formatTime($column, $format = self::DATETIME) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            if (!isset($this->_data[$column])) {
                return $this;
            }if (is_string($this->_data[$column])) {
                $this->_data[$column] = strtotime($this->_data[$column]);
            }if (!is_int($this->_data[$column])) {
                return $this;
            }$this->_data[$column] = date($format, $this->_data[$column]);
            return $this;
        }

        public function insert($table = NULL, Eden_Sql_Database $database = NULL) {
            $error = Eden_Sql_Error::i()->argument(1, 'string', 'null');
            if (is_null($table)) {
                if (!$this->_table) {
                    $error->setMessage(Eden_Sql_Error::TABLE_NOT_SET)->trigger();
                }$table = $this->_table;
            }if (is_null($database)) {
                if (!$this->_database) {
                    $error->setMessage(Eden_Sql_Error::DATABASE_NOT_SET)->trigger();
                }$database = $this->_database;
            }$meta = $this->_getMeta($table, $database);
            $data = $this->_getValidColumns(array_keys($meta[self::COLUMNS]));
            $this->_original = $this->_data;
            $database->insertRow($table, $data);
            if (count($meta[self::PRIMARY]) == 1) {
                $this->_data[$meta[self::PRIMARY][0]] = $database->getLastInsertedId();
            }return $this;
        }

        public function remove($table = NULL, Eden_Sql_Database $database = NULL, $primary = NULL) {
            $error = Eden_Sql_Error::i()->argument(1, 'string', 'null');
            if (is_null($table)) {
                if (!$this->_table) {
                    $error->setMessage(Eden_Sql_Error::TABLE_NOT_SET)->trigger();
                }$table = $this->_table;
            }if (is_null($database)) {
                if (!$this->_database) {
                    $error->setMessage(Eden_Sql_Error::DATABASE_NOT_SET)->trigger();
                }$database = $this->_database;
            }$meta = $this->_getMeta($table, $database);
            $data = $this->_getValidColumns(array_keys($meta[self::COLUMNS]));
            if (is_null($primary)) {
                $primary = $meta[self::PRIMARY];
            }if (is_string($primary)) {
                $primary = array($primary);
            }$filter = array();
            foreach ($primary as $column) {
                if (!isset($data[$column])) {
                    return $this;
                }$filter[] = array($column . '=%s', $data[$column]);
            }$database->deleteRows($table, $filter);
            return $this;
        }

        public function save($table = NULL, Eden_Sql_Database $database = NULL, $primary = NULL) {
            $error = Eden_Sql_Error::i()->argument(1, 'string', 'null');
            if (is_null($table)) {
                if (!$this->_table) {
                    $error->setMessage(Eden_Sql_Error::TABLE_NOT_SET)->trigger();
                }$table = $this->_table;
            }if (is_null($database)) {
                if (!$this->_database) {
                    $error->setMessage(Eden_Sql_Error::DATABASE_NOT_SET)->trigger();
                }$database = $this->_database;
            }$meta = $this->_getMeta($table, $database);
            if (is_null($primary)) {
                $primary = $meta[self::PRIMARY];
            }if (is_string($primary)) {
                $primary = array($primary);
            }$primarySet = $this->_isPrimarySet($primary);
            $this->_original = $this->_data;
            if (empty($primary) || !$primarySet) {
                return $this->insert($table, $database);
            }return $this->update($table, $database, $primary);
        }

        public function setDatabase(Eden_Sql_Database $database) {
            $this->_database = $database;
            return $this;
        }

        public function setTable($table) {
            Eden_Sql_Error::i()->argument(1, 'string');
            $this->_table = $table;
            return $this;
        }

        public function update($table = NULL, Eden_Sql_Database $database = NULL, $primary = NULL) {
            $error = Eden_Sql_Error::i()->argument(1, 'string', 'null');
            if (is_null($table)) {
                if (!$this->_table) {
                    $error->setMessage(Eden_Sql_Error::TABLE_NOT_SET)->trigger();
                }$table = $this->_table;
            }if (is_null($database)) {
                if (!$this->_database) {
                    $error->setMessage(Eden_Sql_Error::DATABASE_NOT_SET)->trigger();
                }$database = $this->_database;
            }$meta = $this->_getMeta($table, $database);
            $data = $this->_getValidColumns(array_keys($meta[self::COLUMNS]));
            $this->_original = $this->_data;
            if (is_null($primary)) {
                $primary = $meta[self::PRIMARY];
            }if (is_string($primary)) {
                $primary = array($primary);
            }$filter = array();
            foreach ($primary as $column) {
                $filter[] = array($column . '=%s', $data[$column]);
            }$database->updateRows($table, $data, $filter);
            return $this;
        }

        protected function _isLoaded($table = NULL, $database = NULL) {
            if (is_null($table)) {
                if (!$this->_table) {
                    return false;
                }$table = $this->_table;
            }if (is_null($database)) {
                if (!$this->_database) {
                    return false;
                }$database = $this->_database;
            }$meta = $this->_getMeta($table, $database);
            return $this->_isPrimarySet($meta[self::PRIMARY]);
        }

        protected function _isPrimarySet(array $primary) {
            foreach ($primary as $column) {
                if (is_null($this[$column])) {
                    return false;
                }
            }return true;
        }

        protected function _getMeta($table, $database) {
            $uid = spl_object_hash($database);
            if (isset(self::$_meta[$uid][$table])) {
                return self::$_meta[$uid][$table];
            }$columns = $database->getColumns($table);
            $meta = array();
            foreach ($columns as $i => $column) {
                $meta[self::COLUMNS][$column['Field']] = array('type' => $column['Type'], 'key' => $column['Key'], 'default' => $column['Default'], 'empty' => $column['Null'] == 'YES');
                if ($column['Key'] == 'PRI') {
                    $meta[self::PRIMARY][] = $column['Field'];
                }
            }self::$_meta[$uid][$table] = $meta;
            return $meta;
        }

        protected function _getValidColumns($columns) {
            $valid = array();
            foreach ($columns as $column) {
                if (!isset($this->_data[$column])) {
                    continue;
                }$valid[$column] = $this->_data[$column];
            }return $valid;
        }

    }

}
/* Eden_Sql_Search */
if (!class_exists('Eden_Sql_Search')) {

    class Eden_Sql_Search extends \Eden {

        const LEFT = 'LEFT';
        const RIGHT = 'RIGHT';
        const INNER = 'INNER';
        const OUTER = 'OUTER';
        const ASC = 'ASC';
        const DESC = 'DESC';

        protected $_database = NULL;
        protected $_table = NULL;
        protected $_columns = array();
        protected $_join = array();
        protected $_filter = array();
        protected $_sort = array();
        protected $_group = array();
        protected $_start = 0;
        protected $_range = 0;
        protected $_model = Eden_Sql_Database::MODEL;
        protected $_collection = Eden_Sql_Database::COLLECTION;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __call($name, $args) {
            if (strpos($name, 'filterBy') === 0) {
                $separator = '_';
                if (isset($args[1]) && is_scalar($args[1])) {
                    $separator = (string) $args[1];
                }$key = Eden_Type_String::i($name)->substr(8)->preg_replace("/([A-Z0-9])/", $separator . "$1")->substr(strlen($separator))->strtolower()->get();
                if (!isset($args[0])) {
                    $args[0] = NULL;
                }$key = $key . '=%s';
                $this->addFilter($key, $args[0]);
                return $this;
            }if (strpos($name, 'sortBy') === 0) {
                $separator = '_';
                if (isset($args[1]) && is_scalar($args[1])) {
                    $separator = (string) $args[1];
                }$key = Eden_Type_String::i($name)->substr(6)->preg_replace("/([A-Z0-9])/", $separator . "$1")->substr(strlen($separator))->strtolower()->get();
                if (!isset($args[0])) {
                    $args[0] = self::ASC;
                }$this->addSort($key, $args[0]);
                return $this;
            }try {
                return parent::__call($name, $args);
            } catch (Eden_Error $e) {
                Eden_Sql_Error::i($e->getMessage())->trigger();
            }
        }

        public function __construct(Eden_Sql_Database $database) {
            $this->_database = $database;
        }

        public function addFilter() {
            Eden_Sql_Error::i()->argument(1, 'string');
            $this->_filter[] = func_get_args();
            return $this;
        }

        public function addInnerJoinOn($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::INNER, $table, $where, false);
            return $this;
        }

        public function addInnerJoinUsing($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::INNER, $table, $where, true);
            return $this;
        }

        public function addLeftJoinOn($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::LEFT, $table, $where, false);
            return $this;
        }

        public function addLeftJoinUsing($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::LEFT, $table, $where, true);
            return $this;
        }

        public function addOuterJoinOn($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::OUTER, $table, $where, false);
            return $this;
        }

        public function addOuterJoinUsing($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::OUTER, $table, $where, true);
            return $this;
        }

        public function addRightJoinOn($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::RIGHT, $table, $where, false);
            return $this;
        }

        public function addRightJoinUsing($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::RIGHT, $table, $where, true);
            return $this;
        }

        public function addSort($column, $order = self::ASC) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            if ($order != self::DESC) {
                $order = self::ASC;
            }$this->_sort[$column] = $order;
            return $this;
        }

        public function getCollection() {
            $collection = $this->_collection;
            return $this->$collection()->setDatabase($this->_database)->setTable($this->_table)->setModel($this->_model)->set($this->getRows());
        }

        public function getModel($index = 0) {
            Eden_Sql_Error::i()->argument(1, 'int');
            return $this->getCollection()->offsetGet($index);
        }

        public function getRow($index = 0, $column = NULL) {
            Eden_Sql_Error::i()->argument(1, 'int', 'string')->argument(2, 'string', 'null');
            if (is_string($index)) {
                $column = $index;
                $index = 0;
            }$rows = $this->getRows();
            if (!is_null($column) && isset($rows[$index][$column])) {
                return $rows[$index][$column];
            } else if (is_null($column) && isset($rows[$index])) {
                return $rows[$index];
            }return NULL;
        }

        public function getRows() {
            $query = $this->_getQuery();
            if (!empty($this->_columns)) {
                $query->select(implode(',', $this->_columns));
            }foreach ($this->_sort as $key => $value) {
                $query->sortBy($key, $value);
            }if ($this->_range) {
                $query->limit($this->_start, $this->_range);
            }if (!empty($this->_group)) {
                $query->groupBy($this->_group);
            }return $this->_database->query($query, $this->_database->getBinds());
        }

        public function getTotal() {
            $query = $this->_getQuery()->select('COUNT(*) as total');
            $rows = $this->_database->query($query, $this->_database->getBinds());
            if (!isset($rows[0]['total'])) {
                return 0;
            }return $rows[0]['total'];
        }

        public function innerJoinOn($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::INNER, $table, $where, false);
            return $this;
        }

        public function innerJoinUsing($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::INNER, $table, $where, true);
            return $this;
        }

        public function leftJoinOn($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::LEFT, $table, $where, false);
            return $this;
        }

        public function leftJoinUsing($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::LEFT, $table, $where, true);
            return $this;
        }

        public function outerJoinOn($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::OUTER, $table, $where, false);
            return $this;
        }

        public function outerJoinUsing($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::OUTER, $table, $where, true);
            return $this;
        }

        public function rightJoinOn($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::RIGHT, $table, $where, false);
            return $this;
        }

        public function rightJoinUsing($table, $where) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $where = func_get_args();
            $table = array_shift($where);
            $this->_join[] = array(self::RIGHT, $table, $where, true);
            return $this;
        }

        public function setColumns($columns) {
            if (!is_array($columns)) {
                $columns = func_get_args();
            }$this->_columns = $columns;
            return $this;
        }

        public function setCollection($collection) {
            $error = Eden_Sql_Error::i()->argument(1, 'string');
            if (!is_subclass_of($collection, 'Eden_Collection')) {
                $error->setMessage(Eden_Sql_Error::NOT_SUB_COLLECTION)->addVariable($collection)->trigger();
            }$this->_collection = $collection;
            return $this;
        }

        public function setGroup($group) {
            Eden_Sql_Error::i()->argument(1, 'string', 'array');
            if (is_string($group)) {
                $group = array($group);
            }$this->_group = $group;
            return $this;
        }

        public function setModel($model) {
            $error = Eden_Sql_Error::i()->argument(1, 'string');
            if (!is_subclass_of($model, 'Eden_Model')) {
                $error->setMessage(Eden_Sql_Error::NOT_SUB_MODEL)->addVariable($model)->trigger();
            }$this->_model = $model;
            return $this;
        }

        public function setPage($page) {
            Eden_Sql_Error::i()->argument(1, 'int');
            if ($page < 1) {
                $page = 1;
            }$this->_start = ($page - 1) * $this->_range;
            return $this;
        }

        public function setRange($range) {
            Eden_Sql_Error::i()->argument(1, 'int');
            if ($range < 0) {
                $range = 25;
            }$this->_range = $range;
            return $this;
        }

        public function setStart($start) {
            Eden_Sql_Error::i()->argument(1, 'int');
            if ($start < 0) {
                $start = 0;
            }$this->_start = $start;
            return $this;
        }

        public function setTable($table) {
            Eden_Sql_Error::i()->argument(1, 'string');
            $this->_table = $table;
            return $this;
        }

        protected function _getQuery() {
            $query = $this->_database->select()->from($this->_table);
            foreach ($this->_join as $join) {
                if (!is_array($join[2])) {
                    $join[2] = array($join[2]);
                }$where = array_shift($join[2]);
                if (!empty($join[2])) {
                    foreach ($join[2] as $i => $value) {
                        $join[2][$i] = $this->_database->bind($value);
                    }$where = vsprintf($where, $join[2]);
                }$query->join($join[0], $join[1], $where, $join[3]);
            }foreach ($this->_filter as $i => $filter) {
                $where = array_shift($filter);
                if (!empty($filter)) {
                    foreach ($filter as $i => $value) {
                        $filter[$i] = $this->_database->bind($value);
                    }$where = vsprintf($where, $filter);
                }$query->where($where);
            }return $query;
        }

    }

}
/* Eden_Mysql_Alter */
if (!class_exists('Eden_Mysql_Alter')) {

    class Eden_Mysql_Alter extends Eden_Sql_Query {

        protected $_name = NULL;
        protected $_changeFields = array();
        protected $_addFields = array();
        protected $_removeFields = array();
        protected $_addKeys = array();
        protected $_removeKeys = array();
        protected $_addUniqueKeys = array();
        protected $_removeUniqueKeys = array();
        protected $_addPrimaryKeys = array();
        protected $_removePrimaryKeys = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($name = NULL) {
            if (is_string($name)) {
                $this->setName($name);
            }
        }

        public function addField($name, array $attributes) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_addFields[$name] = $attributes;
            return $this;
        }

        public function addKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_addKeys[] = '`' . $name . '`';
            return $this;
        }

        public function addPrimaryKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_addPrimaryKeys[] = '`' . $name . '`';
            return $this;
        }

        public function addUniqueKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_addUniqueKeys[] = '`' . $name . '`';
            return $this;
        }

        public function changeField($name, array $attributes) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_changeFields[$name] = $attributes;
            return $this;
        }

        public function getQuery($unbind = false) {
            $fields = array();
            $table = '`' . $this->_name . '`';
            foreach ($this->_removeFields as $name) {
                $fields[] = 'DROP `' . $name . '`';
            }foreach ($this->_addFields as $name => $attr) {
                $field = array('ADD `' . $name . '`');
                if (isset($attr['type'])) {
                    $field[] = isset($attr['length']) ? $attr['type'] . '(' . $attr['length'] . ')' : $attr['type'];
                }if (isset($attr['attribute'])) {
                    $field[] = $attr['attribute'];
                }if (isset($attr['null'])) {
                    if ($attr['null'] == false) {
                        $field[] = 'NOT NULL';
                    } else {
                        $field[] = 'DEFAULT NULL';
                    }
                }if (isset($attr['default']) && $attr['default'] !== false) {
                    if (!isset($attr['null']) || $attr['null'] == false) {
                        if (is_string($attr['default'])) {
                            $field[] = 'DEFAULT \'' . $attr['default'] . '\'';
                        } else if (is_numeric($attr['default'])) {
                            $field[] = 'DEFAULT ' . $attr['default'];
                        }
                    }
                }if (isset($attr['auto_increment']) && $attr['auto_increment'] == true) {
                    $field[] = 'auto_increment';
                }$fields[] = implode(' ', $field);
            }foreach ($this->_changeFields as $name => $attr) {
                $field = array('CHANGE `' . $name . '` `' . $name . '`');
                if (isset($attr['name'])) {
                    $field = array('CHANGE `' . $name . '` `' . $attr['name'] . '`');
                }if (isset($attr['type'])) {
                    $field[] = isset($attr['length']) ? $attr['type'] . '(' . $attr['length'] . ')' : $attr['type'];
                }if (isset($attr['attribute'])) {
                    $field[] = $attr['attribute'];
                }if (isset($attr['null'])) {
                    if ($attr['null'] == false) {
                        $field[] = 'NOT NULL';
                    } else {
                        $field[] = 'DEFAULT NULL';
                    }
                }if (isset($attr['default']) && $attr['default'] !== false) {
                    if (!isset($attr['null']) || $attr['null'] == false) {
                        if (is_string($attr['default'])) {
                            $field[] = 'DEFAULT \'' . $attr['default'] . '\'';
                        } else if (is_numeric($attr['default'])) {
                            $field[] = 'DEFAULT ' . $attr['default'];
                        }
                    }
                }if (isset($attr['auto_increment']) && $attr['auto_increment'] == true) {
                    $field[] = 'auto_increment';
                }$fields[] = implode(' ', $field);
            }foreach ($this->_removeKeys as $key) {
                $fields[] = 'DROP INDEX `' . $key . '`';
            }if (!empty($this->_addKeys)) {
                $fields[] = 'ADD INDEX (' . implode(',', $this->_addKeys) . ')';
            }foreach ($this->_removeUniqueKeys as $key) {
                $fields[] = 'DROP INDEX `' . $key . '`';
            }if (!empty($this->_addUniqueKeys)) {
                $fields[] = 'ADD UNIQUE (' . implode(',', $this->_addUniqueKeys) . ')';
            }foreach ($this->_removePrimaryKeys as $key) {
                $fields[] = 'DROP PRIMARY KEY `' . $key . '`';
            }if (!empty($this->_addPrimaryKeys)) {
                $fields[] = 'ADD PRIMARY KEY (' . implode(',', $this->_addPrimaryKeys) . ')';
            }$fields = implode(",\n", $fields);
            return sprintf('ALTER TABLE %s %s;', $table, $fields);
        }

        public function removeField($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_removeFields[] = $name;
            return $this;
        }

        public function removeKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_removeKeys[] = $name;
            return $this;
        }

        public function removePrimaryKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_removePrimaryKeys[] = $name;
            return $this;
        }

        public function removeUniqueKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_removeUniqueKeys[] = $name;
            return $this;
        }

        public function setName($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_name = $name;
            return $this;
        }

    }

}
/* Eden_Mysql_Create */
if (!class_exists('Eden_Mysql_Create')) {

    class Eden_Mysql_Create extends Eden_Sql_Query {

        protected $_name = NULL;
        protected $_comments = NULL;
        protected $_fields = array();
        protected $_keys = array();
        protected $_uniqueKeys = array();
        protected $_primaryKeys = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($name = NULL) {
            if (is_string($name)) {
                $this->setName($name);
            }
        }

        public function addField($name, array $attributes) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_fields[$name] = $attributes;
            return $this;
        }

        public function addKey($name, array $fields) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_keys[$name] = $fields;
            return $this;
        }

        public function addPrimaryKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_primaryKeys[] = $name;
            return $this;
        }

        public function addUniqueKey($name, array $fields) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_uniqueKeys[$name] = $fields;
            return $this;
        }

        public function getQuery($unbind = false) {
            $table = '`' . $this->_name . '`';
            $fields = array();
            foreach ($this->_fields as $name => $attr) {
                $field = array('`' . $name . '`');
                if (isset($attr['type'])) {
                    $field[] = isset($attr['length']) ? $attr['type'] . '(' . $attr['length'] . ')' : $attr['type'];
                }if (isset($attr['attribute'])) {
                    $field[] = $attr['attribute'];
                }if (isset($attr['null'])) {
                    if ($attr['null'] == false) {
                        $field[] = 'NOT NULL';
                    } else {
                        $field[] = 'DEFAULT NULL';
                    }
                }if (isset($attr['default']) && $attr['default'] !== false) {
                    if (!isset($attr['null']) || $attr['null'] == false) {
                        if (is_string($attr['default'])) {
                            $field[] = 'DEFAULT \'' . $attr['default'] . '\'';
                        } else if (is_numeric($attr['default'])) {
                            $field[] = 'DEFAULT ' . $attr['default'];
                        }
                    }
                }if (isset($attr['auto_increment']) && $attr['auto_increment'] == true) {
                    $field[] = 'auto_increment';
                }$fields[] = implode(' ', $field);
            }$fields = !empty($fields) ? implode(',', $fields) : '';
            $primary = !empty($this->_primaryKeys) ? ',PRIMARY KEY (`' . implode('`,`', $this->_primaryKeys) . '`)' : '';
            $uniques = array();
            foreach ($this->_uniqueKeys as $key => $value) {
                $uniques[] = 'UNIQUE KEY `' . $key . '` (`' . implode('`,`', $value) . '`)';
            }$uniques = !empty($uniques) ? ',' . implode(",\n", $uniques) : '';
            $keys = array();
            foreach ($this->_keys as $key => $value) {
                $keys[] = 'KEY `' . $key . '` (`' . implode('`,`', $value) . '`)';
            }$keys = !empty($keys) ? ',' . implode(",\n", $keys) : '';
            return sprintf('CREATE TABLE %s (%s%s%s%s)', $table, $fields, $primary, $unique, $keys);
        }

        public function setComments($comments) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_comments = $comments;
            return $this;
        }

        public function setFields(array $fields) {
            $this->_fields = $fields;
            return $this;
        }

        public function setKeys(array $keys) {
            $this->_keys = $keys;
            return $this;
        }

        public function setName($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_name = $name;
            return $this;
        }

        public function setPrimaryKeys(array $primaryKeys) {
            $this->_primaryKeys = $primaryKeys;
            return $this;
        }

        public function setUniqueKeys(array $uniqueKeys) {
            $this->_uniqueKeys = $uniqueKeys;
            return $this;
        }

    }

}
/* Eden_Mysql_Subselect */
if (!class_exists('Eden_Mysql_Subselect')) {

    class Eden_Mysql_Subselect extends \Eden {

        protected $_parentQuery;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct(Eden_Sql_Select $parentQuery, $select = '*') {
            Eden_Mysql_Error::i()->argument(2, 'string');
            $this->setParentQuery($parentQuery);
            $this->_select = is_array($select) ? implode(',', $select) : $select;
        }

        public function getQuery() {
            return '(' . substr(parent::getQuery(), 0, -1) . ')';
        }

        public function setParentQuery(Eden_Sql_Select $parentQuery) {
            $this->_parentQuery = $parentQuery;
            return $this;
        }

    }

}
/* Eden_Mysql_Utility */
if (!class_exists('Eden_Mysql_Utility')) {

    class Eden_Mysql_Utility extends Eden_Sql_Query {

        protected $_query = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function dropTable($table) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_query = 'DROP TABLE `' . $table . '`';
            return $this;
        }

        public function getQuery() {
            return $this->_query . ';';
        }

        public function renameTable($table, $name) {
            Eden_Mysql_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query = 'RENAME TABLE `' . $table . '` TO `' . $name . '`';
            return $this;
        }

        public function showColumns($table, $where = NULL) {
            Eden_Mysql_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            $where = $where ? ' WHERE ' . $where : NULL;
            $this->_query = 'SHOW FULL COLUMNS FROM `' . $table . '`' . $where;
            return $this;
        }

        public function showTables($like = NULL) {
            Eden_Mysql_Error::i()->argument(1, 'string', 'null');
            $like = $like ? ' LIKE ' . $like : NULL;
            $this->_query = 'SHOW TABLES' . $like;
            return $this;
        }

        public function truncate($table) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_query = 'TRUNCATE `' . $table . '`';
            return $this;
        }

    }

}
/* Eden_Mysql */
if (!class_exists('Eden_Mysql')) {

    class Eden_Mysql extends Eden_Sql_Database {

        protected $_host = 'localhost';
        protected $_name = NULL;
        protected $_user = NULL;
        protected $_pass = NULL;
        protected $_model = self::MODEL;
        protected $_collection = self::COLLECTION;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($host, $name, $user, $pass = NULL, $port = NULL) {
            Eden_Mysql_Error::i()->argument(1, 'string', 'null')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string', 'null')->argument(5, 'numeric', 'null');
            $this->_host = $host;
            $this->_name = $name;
            $this->_user = $user;
            $this->_pass = $pass;
            $this->_port = $port;
        }

        public function alter($name = NULL) {
            Eden_Mysql_Error::i()->argument(1, 'string', 'null');
            return Eden_Mysql_Alter::i($name);
        }

        public function create($name = NULL) {
            Eden_Mysql_Error::i()->argument(1, 'string', 'null');
            return Eden_Mysql_Create::i($name);
        }

        public function connect(array $options = array()) {
            $host = $port = NULL;
            if (!is_null($this->_host)) {
                $host = 'host=' . $this->_host . ';';
                if (!is_null($this->_port)) {
                    $port = 'port=' . $this->_port . ';';
                }
            }$connection = 'mysql:' . $host . $port . 'dbname=' . $this->_name;
            $this->_connection = new PDO($connection, $this->_user, $this->_pass, $options);
            $this->trigger();
            return $this;
        }

        public function subselect($parentQuery, $select = '*') {
            Eden_Mysql_Error::i()->argument(2, 'string');
            return Eden_Mysql_Subselect::i($parentQuery, $select);
        }

        public function utility() {
            return Eden_Mysql_Utility::i();
        }

        public function getColumns($table, $filters = NULL) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $query = $this->utility();
            if (is_array($filters)) {
                foreach ($filters as $i => $filter) {
                    $format = array_shift($filter);
                    $filter = $this->bind($filter);
                    $filters[$i] = vsprintf($format, $filter);
                }
            }$query->showColumns($table, $filters);
            return $this->query($query, $this->getBinds());
        }

        public function getPrimaryKey($table) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $query = $this->utility();
            $results = $this->getColumns($table, "`Key`='PRI'");
            return isset($results[0]['Field']) ? $results[0]['Field'] : NULL;
        }

        public function getSchema() {
            $backup = array();
            $tables = $this->getTables();
            foreach ($tables as $table) {
                $backup[] = $this->getBackup();
            }return implode("\n\n", $backup);
        }

        public function getTables($like = NULL) {
            Eden_Mysql_Error::i()->argument(1, 'string', 'null');
            $query = $this->utility();
            $like = $like ? $this->bind($like) : NULL;
            $results = $this->query($query->showTables($like), $q->getBinds());
            $newResults = array();
            foreach ($results as $result) {
                foreach ($result as $key => $value) {
                    $newResults[] = $value;
                    break;
                }
            }return $newResults;
        }

        public function getTableSchema($table) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $backup = array();
            $schema = $this->getColumns($table);
            if (count($schema)) {
                $query = $this->create()->setName($table);
                foreach ($schema as $field) {
                    $fieldTypeArray = explode(' ', $field['Type']);
                    $typeArray = explode('(', $fieldTypeArray[0]);
                    $type = $typeArray[0];
                    $length = str_replace(')', '', $typeArray[1]);
                    $attribute = isset($fieldTypeArray[1]) ? $fieldTypeArray[1] : NULL;
                    $null = strtolower($field['Null']) == 'no' ? false : true;
                    $increment = strtolower($field['Extra']) == 'auto_increment' ? true : false;
                    $q->addField($field['Field'], array('type' => $type, 'length' => $length, 'attribute' => $attribute, 'null' => $null, 'default' => $field['Default'], 'auto_increment' => $increment));
                    switch ($field['Key']) {
                        case 'PRI': $query->addPrimaryKey($field['Field']);
                            break;
                        case 'UNI': $query->addUniqueKey($field['Field'], array($field['Field']));
                            break;
                        case 'MUL': $query->addKey($field['Field'], array($field['Field']));
                            break;
                    }
                }$backup[] = $query;
            }$rows = $this->query($this->select->from($table)->getQuery());
            if (count($rows)) {
                $query = $this->insert($table);
                foreach ($rows as $index => $row) {
                    foreach ($row as $key => $value) {
                        $query->set($key, $this->getBinds($value), $index);
                    }
                }$backup[] = $query->getQuery(true);
            }return implode("\n\n", $backup);
        }

    }

}
/* Eden_Postgre_Error */
if (!class_exists('Eden_Postgre_Error')) {

    class Eden_Postgre_Error extends Eden_Sql_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Postgre_Alter */
if (!class_exists('Eden_Postgre_Alter')) {

    class Eden_Postgre_Alter extends Eden_Sql_Query {

        protected $_name = NULL;
        protected $_changeFields = array();
        protected $_addFields = array();
        protected $_removeFields = array();
        protected $_addPrimaryKeys = array();
        protected $_removePrimaryKeys = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($name = NULL) {
            if (is_string($name)) {
                $this->setName($name);
            }
        }

        public function addField($name, array $attributes) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_addFields[$name] = $attributes;
            return $this;
        }

        public function addPrimaryKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_addPrimaryKeys[] = '"' . $name . '"';
            return $this;
        }

        public function changeField($name, array $attributes) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_changeFields[$name] = $attributes;
            return $this;
        }

        public function getQuery($unbind = false) {
            $fields = array();
            $table = '"' . $this->_name . '""';
            foreach ($this->_removeFields as $name) {
                $fields[] = 'DROP COLUMN "' . $name . '"';
            }foreach ($this->_addFields as $name => $attr) {
                $field = array('ADD "' . $name . '"');
                if (isset($attr['type'])) {
                    $field[] = isset($attr['length']) ? $attr['type'] . '(' . $attr['length'] . ')' : $attr['type'];
                    if (isset($attr['list']) && $attr['list']) {
                        $field[count($field) - 1].='[]';
                    }
                }if (isset($attr['attribute'])) {
                    $field[] = $attr['attribute'];
                }if (isset($attr['unique']) && $attr['unique']) {
                    $field[] = 'UNIQUE';
                }if (isset($attr['null'])) {
                    if ($attr['null'] == false) {
                        $field[] = 'NOT NULL';
                    } else {
                        $field[] = 'DEFAULT NULL';
                    }
                }if (isset($attr['default']) && $attr['default'] !== false) {
                    if (!isset($attr['null']) || $attr['null'] == false) {
                        if (is_string($attr['default'])) {
                            $field[] = 'DEFAULT \'' . $attr['default'] . '\'';
                        } else if (is_numeric($attr['default'])) {
                            $field[] = 'DEFAULT ' . $attr['default'];
                        }
                    }
                }$fields[] = implode(' ', $field);
            }foreach ($this->_changeFields as $name => $attr) {
                $field = array('ALTER COLUMN "' . $name . '"');
                if (isset($attr['name'])) {
                    $field = array('CHANGE "' . $name . '" "' . $attr['name'] . '"');
                }if (isset($attr['type'])) {
                    $field[] = isset($attr['length']) ? $attr['type'] . '(' . $attr['length'] . ')' : $attr['type'];
                    if (isset($attr['list']) && $attr['list']) {
                        $field[count($field) - 1].='[]';
                    }
                }if (isset($attr['attribute'])) {
                    $field[] = $attr['attribute'];
                }if (isset($attr['unique']) && $attr['unique']) {
                    $field[] = 'UNIQUE';
                }if (isset($attr['null'])) {
                    if ($attr['null'] == false) {
                        $field[] = 'NOT NULL';
                    } else {
                        $field[] = 'DEFAULT NULL';
                    }
                }if (isset($attr['default']) && $attr['default'] !== false) {
                    if (!isset($attr['null']) || $attr['null'] == false) {
                        if (is_string($attr['default'])) {
                            $field[] = 'DEFAULT \'' . $attr['default'] . '\'';
                        } else if (is_numeric($attr['default'])) {
                            $field[] = 'DEFAULT ' . $attr['default'];
                        }
                    }
                }$fields[] = implode(' ', $field);
            }foreach ($this->_removePrimaryKeys as $key) {
                $fields[] = 'DROP PRIMARY KEY "' . $key . '"';
            }if (!empty($this->_addPrimaryKeys)) {
                $fields[] = 'ADD PRIMARY KEY (' . implode(',', $this->_addPrimaryKeys) . ')';
            }$fields = implode(",\n", $fields);
            return sprintf('ALTER TABLE %s %s;', $table, $fields);
        }

        public function removeField($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_removeFields[] = $name;
            return $this;
        }

        public function removePrimaryKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_removePrimaryKeys[] = $name;
            return $this;
        }

        public function setName($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_name = $name;
            return $this;
        }

    }

}
/* Eden_Postgre_Create */
if (!class_exists('Eden_Postgre_Create')) {

    class Eden_Postgre_Create extends Eden_Sql_Query {

        protected $_name = NULL;
        protected $_fields = array();
        protected $_primaryKeys = array();
        protected $_oids = false;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($name = NULL) {
            if (is_string($name)) {
                $this->setName($name);
            }
        }

        public function addField($name, array $attributes) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_fields[$name] = $attributes;
            return $this;
        }

        public function addPrimaryKey($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_primaryKeys[] = $name;
            return $this;
        }

        public function getQuery($unbind = false) {
            $table = '"' . $this->_name . '"';
            $fields = array();
            foreach ($this->_fields as $name => $attr) {
                $field = array('"' . $name . '"');
                if (isset($attr['type'])) {
                    $field[] = isset($attr['length']) ? $attr['type'] . '(' . $attr['length'] . ')' : $attr['type'];
                    if (isset($attr['list']) && $attr['list']) {
                        $field[count($field) - 1].='[]';
                    }
                }if (isset($attr['attribute'])) {
                    $field[] = $attr['attribute'];
                }if (isset($attr['unique']) && $attr['unique']) {
                    $field[] = 'UNIQUE';
                }if (isset($attr['null'])) {
                    if ($attr['null'] == false) {
                        $field[] = 'NOT NULL';
                    } else {
                        $field[] = 'DEFAULT NULL';
                    }
                }if (isset($attr['default']) && $attr['default'] !== false) {
                    if (!isset($attr['null']) || $attr['null'] == false) {
                        if (is_string($attr['default'])) {
                            $field[] = 'DEFAULT \'' . $attr['default'] . '\'';
                        } else if (is_numeric($attr['default'])) {
                            $field[] = 'DEFAULT ' . $attr['default'];
                        }
                    }
                }$fields[] = implode(' ', $field);
            }$oids = $this->_oids ? 'WITH OIDS' : NULL;
            $fields = !empty($fields) ? implode(',', $fields) : '';
            $primary = !empty($this->_primaryKeys) ? ',PRIMARY KEY ("' . implode('",""', $this->_primaryKeys) . '")' : '';
            return sprintf('CREATE TABLE %s (%s%s) %s', $table, $fields, $primary, $oids);
        }

        public function setFields(array $fields) {
            $this->_fields = $fields;
            return $this;
        }

        public function setName($name) {
            Eden_Mysql_Error::i()->argument(1, 'string');
            $this->_name = $name;
            return $this;
        }

        public function setPrimaryKeys(array $primaryKeys) {
            $this->_primaryKeys = $primaryKeys;
            return $this;
        }

        public function withOids($oids) {
            Eden_Mysql_Error::i()->argument(1, 'bool');
            $this->_oids = $oids;
            return $this;
        }

    }

}
/* Eden_Postgre_Delete */
if (!class_exists('Eden_Postgre_Delete')) {

    class Eden_Postgre_Delete extends Eden_Sql_Delete {

        protected $_table = NULL;
        protected $_where = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($table = NULL) {
            if (is_string($table)) {
                $this->setTable($table);
            }
        }

        public function getQuery() {
            return 'DELETE FROM "' . $this->_table . '" WHERE ' . implode(' AND ', $this->_where) . ';';
        }

    }

}
/* Eden_Postgre_Insert */
if (!class_exists('Eden_Postgre_Insert')) {

    class Eden_Postgre_Insert extends Eden_Sql_Insert {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getQuery() {
            $multiValList = array();
            foreach ($this->_setVal as $val) {
                $multiValList[] = '(' . implode(',', $val) . ')';
            }return 'INSERT INTO "' . $this->_table . '" ("' . implode('","', $this->_setKey) . '") VALUES ' . implode(",\n", $multiValList) . ';';
        }

        public function set($key, $value, $index = 0) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'scalar', 'null');
            if (!in_array($key, $this->_setKey)) {
                $this->_setKey[] = $key;
            }if (is_null($value)) {
                $value = 'NULL';
            } else if (is_bool($value)) {
                $value = $value ? 'TRUE' : 'FALSE';
            }$this->_setVal[$index][] = $value;
            return $this;
        }

    }

}
/* Eden_Postgre_Select */
if (!class_exists('Eden_Postgre_Select')) {

    class Eden_Postgre_Select extends Eden_Sql_Select {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getQuery() {
            $joins = empty($this->_joins) ? '' : implode(' ', $this->_joins);
            $where = empty($this->_where) ? '' : 'WHERE ' . implode(' AND ', $this->_where);
            $sort = empty($this->_sortBy) ? '' : 'ORDER BY ' . implode(',', $this->_sortBy);
            $limit = is_null($this->_page) ? '' : 'LIMIT ' . $this->_page . ' OFFSET ' . $this->_length;
            $group = empty($this->_group) ? '' : 'GROUP BY ' . implode(',', $this->_group);
            $query = sprintf('SELECT %s FROM %s %s %s %s %s %s;', $this->_select, $this->_from, $joins, $where, $group, $sort, $limit);
            return str_replace(' ', ' ', $query);
        }

    }

}
/* Eden_Postgre_Update */
if (!class_exists('Eden_Postgre_Update')) {

    class Eden_Postgre_Update extends Eden_Postgre_Delete {

        protected $_set = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getQuery() {
            $set = array();
            foreach ($this->_set as $key => $value) {
                $set[] = '"' . $key . '"=' . $value;
            }return 'UPDATE ' . $this->_table . ' SET ' . implode(',', $set) . ' WHERE ' . implode(' AND ', $this->_where) . ';';
        }

        public function set($key, $value) {
            Eden_Sql_Error::i()->argument(1, 'string')->argument(2, 'scalar', 'null');
            if (is_null($value)) {
                $value = 'NULL';
            } else if (is_bool($value)) {
                $value = $value ? 'TRUE' : 'FALSE';
            }$this->_set[$key] = $value;
            return $this;
        }

    }

}
/* Eden_Postgre_Utility */
if (!class_exists('Eden_Postgre_Utility')) {

    class Eden_Postgre_Utility extends Eden_Sql_Query {

        protected $_query = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function dropTable($table) {
            Eden_Postgre_Error::i()->argument(1, 'string');
            $this->_query = 'DROP TABLE "' . $table . '"';
            return $this;
        }

        public function getQuery() {
            return $this->_query . ';';
        }

        public function renameTable($table, $name) {
            Eden_Postgre_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query = 'RENAME TABLE "' . $table . '" TO "' . $name . '"';
            return $this;
        }

        public function setSchema($schema) {
            $this->_query = 'SET search_path TO ' . $schema;
            return $this;
        }

        public function truncate($table) {
            Eden_Postgre_Error::i()->argument(1, 'string');
            $this->_query = 'TRUNCATE "' . $table . '"';
            return $this;
        }

    }

}
/* Eden_Postgre */
if (!class_exists('Eden_Postgre')) {

    class Eden_Postgre extends Eden_Sql_Database {

        protected $_host = 'localhost';
        protected $_port = NULL;
        protected $_name = NULL;
        protected $_user = NULL;
        protected $_pass = NULL;
        protected $_model = self::MODEL;
        protected $_collection = self::COLLECTION;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($host, $name, $user, $pass = NULL, $port = NULL) {
            Eden_Postgre_Error::i()->argument(1, 'string', 'null')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string', 'null')->argument(5, 'numeric', 'null');
            $this->_host = $host;
            $this->_name = $name;
            $this->_user = $user;
            $this->_pass = $pass;
            $this->_port = $port;
        }

        public function alter($name = NULL) {
            Eden_Postgre_Error::i()->argument(1, 'string', 'null');
            return Eden_Postgre_Alter::i($name);
        }

        public function connect(array $options = array()) {
            $host = $port = NULL;
            if (!is_null($this->_host)) {
                $host = 'host=' . $this->_host . ';';
                if (!is_null($this->_port)) {
                    $port = 'port=' . $this->_port . ';';
                }
            }$connection = 'pgsql:' . $host . $port . 'dbname=' . $this->_name;
            $this->_connection = new PDO($connection, $this->_user, $this->_pass, $options);
            $this->trigger();
            return $this;
        }

        public function create($name = NULL) {
            Eden_Postgre_Error::i()->argument(1, 'string', 'null');
            return Eden_Postgre_Create::i($name);
        }

        public function delete($table = NULL) {
            Eden_Postgre_Error::i()->argument(1, 'string', 'null');
            return Eden_Postgre_Delete::i($table);
        }

        public function getColumns($table, $schema = NULL) {
            Eden_Postgre_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            $select = array('columns.table_schema', 'columns.column_name', 'columns.ordinal_position', 'columns.column_default', 'columns.is_nullable', 'columns.data_type', 'columns.character_maximum_length', 'columns.character_octet_length', 'pg_class2.relname AS index_type');
            $where = array("pg_attribute.attrelid=pg_class1.oid AND pg_class1.relname='" . $table . "'", 'columns.column_name=pg_attribute.attname AND columns.table_name=pg_class1.relname', 'pg_class1.oid=pg_index.indrelid AND pg_attribute.attnum=ANY(pg_index.indkey)', 'pg_class2.oid=pg_index.indexrelid');
            if ($schema) {
                $where[1].=' AND columns.table_schema="' . $schema . '"';
            }$query = Eden_Postgre_Select::i()->select($select)->from('pg_attribute')->innerJoin('pg_class AS pg_class1', $where[0], false)->innerJoin('information_schema.COLUMNS	AS columns', $where[1], false)->leftJoin('pg_index', $where[2], false)->leftJoin('pg_class AS pg_class2', $where[3], false)->getQuery();
            $results = $this->query($query);
            $columns = array();
            foreach ($results as $column) {
                $key = NULL;
                if (strpos($column['index_type'], '_pkey') !== false) {
                    $key = 'PRI';
                } else if (strpos($column['index_type'], '_key') !== false) {
                    $key = 'UNI';
                }$columns[] = array('Field' => $column['column_name'], 'Type' => $column['data_type'], 'Default' => $column['column_default'], 'Null' => $column['is_nullable'], 'Key' => $key);
            }return $columns;
        }

        public function getIndexes($table, $schema = NULL) {
            Eden_Postgre_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            $select = array('columns.column_name', 'pg_class2.relname AS index_type');
            $where = array("pg_attribute.attrelid=pg_class1.oid AND pg_class1.relname='" . $table . "'", 'columns.column_name=pg_attribute.attname AND columns.table_name=pg_class1.relname', 'pg_class1.oid=pg_index.indrelid AND pg_attribute.attnum=ANY(pg_index.indkey)', 'pg_class2.oid=pg_index.indexrelid');
            if ($schema) {
                $where[1].=' AND columns.table_schema="' . $schema . '"';
            }$query = Eden_Postgre_Select::i()->select($select)->from('pg_attribute')->innerJoin('pg_class AS pg_class1', $where[0], false)->innerJoin('information_schema.COLUMNS	AS columns', $where[1], false)->innerJoin('pg_index', $where[2], false)->innerJoin('pg_class AS pg_class2', $where[3], false)->getQuery();
            return $this->query($query);
        }

        public function getPrimary($table, $schema = NULL) {
            Eden_Postgre_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            $select = array('columns.column_name');
            $where = array("pg_attribute.attrelid=pg_class1.oid AND pg_class1.relname='" . $table . "'", 'columns.column_name=pg_attribute.attname AND columns.table_name=pg_class1.relname', 'pg_class1.oid=pg_index.indrelid AND pg_attribute.attnum=ANY(pg_index.indkey)', 'pg_class2.oid=pg_index.indexrelid');
            if ($schema) {
                $where[1].=' AND columns.table_schema="' . $schema . '"';
            }$query = Eden_Postgre_Select::i()->select($select)->from('pg_attribute')->innerJoin('pg_class AS pg_class1', $where[0], false)->innerJoin('information_schema.COLUMNS	AS columns', $where[1], false)->innerJoin('pg_index', $where[2], false)->innerJoin('pg_class AS pg_class2', $where[3], false)->where('pg_class2.relname LIKE \'%_pkey\'')->getQuery();
            return $this->query($query);
        }

        public function getTables() {
            $query = Eden_Postgre_Select::i()->select('tablename')->from('pg_tables')->where("tablename NOT LIKE 'pg\\_%'")->where("tablename NOT LIKE 'sql\\_%'")->getQuery();
            return $this->query($query);
        }

        public function insert($table = NULL) {
            Eden_Postgre_Error::i()->argument(1, 'string', 'null');
            return Eden_Postgre_Insert::i($table);
        }

        public function select($select = '*') {
            Eden_Postgre_Error::i()->argument(1, 'string', 'array');
            return Eden_Postgre_Select::i($select);
        }

        public function setSchema($schema) {
            $schema = array($schema);
            if (func_num_args() > 0) {
                $schema = func_get_args();
            }$error = Eden_Postgre_Error::i();
            foreach ($schema as $i => $name) {
                $error->argument($i + 1, 'string');
            }$schema = implode(',', $schema);
            $query = $this->utility()->setSchema($schema);
            $this->query($query);
            return $this;
        }

        public function update($table = NULL) {
            Eden_Postgre_Error::i()->argument(1, 'string', 'null');
            return Eden_Postgre_Update::i($table);
        }

        public function utility() {
            return Eden_Postgre_Utility::i();
        }

    }

}
/* Eden_Sqlite_Error */
if (!class_exists('Eden_Sqlite_Error')) {

    class Eden_Sqlite_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Sqlite_Alter */
if (!class_exists('Eden_Sqlite_Alter')) {

    class Eden_Sqlite_Alter extends Eden_Sql_Query {

        protected $_name = NULL;
        protected $_changeFields = array();
        protected $_addFields = array();
        protected $_removeFields = array();
        protected $_addKeys = array();
        protected $_removeKeys = array();
        protected $_addUniqueKeys = array();
        protected $_removeUniqueKeys = array();
        protected $_addPrimaryKeys = array();
        protected $_removePrimaryKeys = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($name = NULL) {
            if (is_string($name)) {
                $this->setName($name);
            }
        }

        public function addField($name, array $attributes) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_addFields[$name] = $attributes;
            return $this;
        }

        public function addForeignKey($name, $table, $key) {
            Eden_Sqlite_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_addKeys[$name] = array($table, $key);
            return $this;
        }

        public function addUniqueKey($name) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_addUniqueKeys[] = '"' . $name . '"';
            return $this;
        }

        public function changeField($name, array $attributes) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_changeFields[$name] = $attributes;
            return $this;
        }

        public function getQuery($unbind = false) {
            $fields = array();
            $table = '"' . $this->_name . '"';
            foreach ($this->_removeFields as $name) {
                $fields[] = 'DROP "' . $name . '"';
            }foreach ($this->_addFields as $name => $attr) {
                $field = array('ADD "' . $name . '"');
                if (isset($attr['type'])) {
                    $field[] = isset($attr['length']) ? $attr['type'] . '(' . $attr['length'] . ')' : $attr['type'];
                }if (isset($attr['attribute'])) {
                    $field[] = $attr['attribute'];
                }if (isset($attr['null'])) {
                    if ($attr['null'] == false) {
                        $field[] = 'NOT NULL';
                    } else {
                        $field[] = 'DEFAULT NULL';
                    }
                }if (isset($attr['default']) && $attr['default'] !== false) {
                    if (!isset($attr['null']) || $attr['null'] == false) {
                        if (is_string($attr['default'])) {
                            $field[] = 'DEFAULT \'' . $attr['default'] . '\'';
                        } else if (is_numeric($attr['default'])) {
                            $field[] = 'DEFAULT ' . $attr['default'];
                        }
                    }
                }$fields[] = implode(' ', $field);
            }foreach ($this->_changeFields as $name => $attr) {
                $field = array('CHANGE "' . $name . '" "' . $name . '"');
                if (isset($attr['name'])) {
                    $field = array('CHANGE "' . $name . '" "' . $attr['name'] . '"');
                }if (isset($attr['type'])) {
                    $field[] = isset($attr['length']) ? $attr['type'] . '(' . $attr['length'] . ')' : $attr['type'];
                }if (isset($attr['attribute'])) {
                    $field[] = $attr['attribute'];
                }if (isset($attr['null'])) {
                    if ($attr['null'] == false) {
                        $field[] = 'NOT NULL';
                    } else {
                        $field[] = 'DEFAULT NULL';
                    }
                }if (isset($attr['default']) && $attr['default'] !== false) {
                    if (!isset($attr['null']) || $attr['null'] == false) {
                        if (is_string($attr['default'])) {
                            $field[] = 'DEFAULT \'' . $attr['default'] . '\'';
                        } else if (is_numeric($attr['default'])) {
                            $field[] = 'DEFAULT ' . $attr['default'];
                        }
                    }
                }$fields[] = implode(' ', $field);
            }foreach ($this->_removeKeys as $key) {
                $fields[] = 'DROP FOREIGN KEY "' . $key . '"';
            }foreach ($this->_keys as $key => $value) {
                $fields[] = 'ADD FOREIGN KEY "' . $key . '" REFERENCES ' . $value[0] . '(' . $value[1] . ')';
            }foreach ($this->_removeUniqueKeys as $key) {
                $fields[] = 'DROP UNIQUE "' . $key . '"';
            }if (!empty($this->_addUniqueKeys)) {
                $fields[] = 'ADD UNIQUE (' . implode(',', $this->_addUniqueKeys) . ')';
            }$fields = implode(",\n", $fields);
            return sprintf('ALTER TABLE %s %s;', $table, $fields);
        }

        public function removeField($name) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_removeFields[] = $name;
            return $this;
        }

        public function removeForeignKey($name) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_removeKeys[] = $name;
            return $this;
        }

        public function removeUniqueKey($name) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_removeUniqueKeys[] = $name;
            return $this;
        }

        public function setName($name) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_name = $name;
            return $this;
        }

    }

}
/* Eden_Sqlite_Create */
if (!class_exists('Eden_Sqlite_Create')) {

    class Eden_Sqlite_Create extends Eden_Sql_Query {

        protected $_name = NULL;
        protected $_comments = NULL;
        protected $_fields = array();
        protected $_keys = array();
        protected $_uniqueKeys = array();
        protected $_primaryKeys = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($name = NULL) {
            if (is_string($name)) {
                $this->setName($name);
            }
        }

        public function addField($name, array $attributes) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_fields[$name] = $attributes;
            return $this;
        }

        public function addForeignKey($name, $table, $key) {
            Eden_Sqlite_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_keys[$name] = array($table, $key);
            return $this;
        }

        public function addUniqueKey($name, array $fields) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_uniqueKeys[$name] = $fields;
            return $this;
        }

        public function getQuery($unbind = false) {
            $table = '"' . $this->_name . '"';
            $fields = array();
            foreach ($this->_fields as $name => $attr) {
                $field = array('"' . $name . '"');
                if (isset($attr['type'])) {
                    $field[] = isset($attr['length']) ? $attr['type'] . '(' . $attr['length'] . ')' : $attr['type'];
                }if (isset($attr['primary'])) {
                    $field[] = 'PRIMARY KEY';
                }if (isset($attr['attribute'])) {
                    $field[] = $attr['attribute'];
                }if (isset($attr['null'])) {
                    if ($attr['null'] == false) {
                        $field[] = 'NOT NULL';
                    } else {
                        $field[] = 'DEFAULT NULL';
                    }
                }if (isset($attr['default']) && $attr['default'] !== false) {
                    if (!isset($attr['null']) || $attr['null'] == false) {
                        if (is_string($attr['default'])) {
                            $field[] = 'DEFAULT \'' . $attr['default'] . '\'';
                        } else if (is_numeric($attr['default'])) {
                            $field[] = 'DEFAULT ' . $attr['default'];
                        }
                    }
                }$fields[] = implode(' ', $field);
            }$fields = !empty($fields) ? implode(',', $fields) : '';
            $uniques = array();
            foreach ($this->_uniqueKeys as $key => $value) {
                $uniques[] = 'UNIQUE "' . $key . '" ("' . implode('","', $value) . '")';
            }$uniques = !empty($uniques) ? ',' . implode(",\n", $uniques) : '';
            $keys = array();
            foreach ($this->_keys as $key => $value) {
                $keys[] = 'FOREIGN KEY "' . $key . '" REFERENCES ' . $value[0] . '(' . $value[1] . ')';
            }$keys = !empty($keys) ? ',' . implode(",\n", $keys) : '';
            return sprintf('CREATE TABLE %s (%s%s%s)', $table, $fields, $unique, $keys);
        }

        public function setComments($comments) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_comments = $comments;
            return $this;
        }

        public function setFields(array $fields) {
            $this->_fields = $fields;
            return $this;
        }

        public function setForiegnKeys(array $keys) {
            $this->_keys = $keys;
            return $this;
        }

        public function setName($name) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_name = $name;
            return $this;
        }

        public function setUniqueKeys(array $uniqueKeys) {
            $this->_uniqueKeys = $uniqueKeys;
            return $this;
        }

    }

}
/* Eden_Sqlite_Utility */
if (!class_exists('Eden_Sqlite_Utility')) {

    class Eden_Sqlite_Utility extends Eden_Sql_Query {

        protected $_query = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function dropTable($table) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_query = 'DROP TABLE "' . $table . '"';
            return $this;
        }

        public function getQuery() {
            return $this->_query . ';';
        }

        public function renameTable($table, $name) {
            Eden_Sqlite_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query = 'RENAME TABLE "' . $table . '" TO "' . $name . '"';
            return $this;
        }

        public function showColumns($table) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_query = 'PRAGMA table_info(' . $table . ')';
            return $this;
        }

        public function showTables() {
            $this->_query = 'SELECT * FROM dbname.sqlite_master WHERE type=\'table\'';
            return $this;
        }

        public function truncate($table) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_query = 'TRUNCATE "' . $table . '"';
            return $this;
        }

    }

}
/* Eden_Sqlite */
if (!class_exists('Eden_Sqlite')) {

    class Eden_Sqlite extends Eden_Sql_Database {

        protected $_file = NULL;
        protected $_model = self::MODEL;
        protected $_collection = self::COLLECTION;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($file) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $this->_file = $file;
        }

        public function alter($name = NULL) {
            Eden_Sqlite_Error::i()->argument(1, 'string', 'null');
            return Eden_Sqlite_Alter::i($name);
        }

        public function connect(array $options = array()) {
            $this->_connection = new PDO('sqlite:' . $this->_file);
            $this->_connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->trigger('connect');
            return $this;
        }

        public function create($name = NULL) {
            Eden_Sqlite_Error::i()->argument(1, 'string', 'null');
            return Eden_Sqlite_Create::i($name);
        }

        public function getColumns($table) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $query = $this->utility()->showColumns($table);
            $results = $this->query($query, $this->getBinds());
            $columns = array();
            foreach ($results as $column) {
                $key = NULL;
                if ($column['pk'] == 1) {
                    $key = 'PRI';
                }$columns[] = array('Field' => $column['name'], 'Type' => $column['type'], 'Default' => $column['dflt_value'], 'Null' => $column['notnull'] != 1, 'Key' => $key);
            }return $columns;
        }

        public function getPrimaryKey($table) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $query = $this->utility();
            $results = $this->getColumns($table, "`Key`='PRI'");
            return isset($results[0]['Field']) ? $results[0]['Field'] : NULL;
        }

        public function getSchema() {
            $backup = array();
            $tables = $this->getTables();
            foreach ($tables as $table) {
                $backup[] = $this->getBackup();
            }return implode("\n\n", $backup);
        }

        public function getTableSchema($table) {
            Eden_Sqlite_Error::i()->argument(1, 'string');
            $backup = array();
            $schema = $this->getColumns($table);
            if (count($schema)) {
                $query = $this->create()->setName($table);
                foreach ($schema as $field) {
                    $fieldTypeArray = explode(' ', $field['Type']);
                    $typeArray = explode('(', $fieldTypeArray[0]);
                    $type = $typeArray[0];
                    $length = str_replace(')', '', $typeArray[1]);
                    $attribute = isset($fieldTypeArray[1]) ? $fieldTypeArray[1] : NULL;
                    $null = strtolower($field['Null']) == 'no' ? false : true;
                    $increment = strtolower($field['Extra']) == 'auto_increment' ? true : false;
                    $q->addField($field['Field'], array('type' => $type, 'length' => $length, 'attribute' => $attribute, 'null' => $null, 'default' => $field['Default'], 'auto_increment' => $increment));
                    switch ($field['Key']) {
                        case 'PRI': $query->addPrimaryKey($field['Field']);
                            break;
                        case 'UNI': $query->addUniqueKey($field['Field'], array($field['Field']));
                            break;
                        case 'MUL': $query->addKey($field['Field'], array($field['Field']));
                            break;
                    }
                }$backup[] = $query;
            }$rows = $this->query($this->select->from($table)->getQuery());
            if (count($rows)) {
                $query = $this->insert($table);
                foreach ($rows as $index => $row) {
                    foreach ($row as $key => $value) {
                        $query->set($key, $this->getBinds($value), $index);
                    }
                }$backup[] = $query->getQuery(true);
            }return implode("\n\n", $backup);
        }

        public function getTables($like = NULL) {
            Eden_Sqlite_Error::i()->argument(1, 'string', 'null');
            $query = $this->utility();
            $like = $like ? $this->bind($like) : NULL;
            $results = $this->query($query->showTables($like), $q->getBinds());
            $newResults = array();
            foreach ($results as $result) {
                foreach ($result as $key => $value) {
                    $newResults[] = $value;
                    break;
                }
            }return $newResults;
        }

        public function select($select = 'ROWID,*') {
            Eden_Sqlite_Error::i()->argument(1, 'string', 'array');
            return Eden_Sql_Select::i($select);
        }

        public function utility() {
            return Eden_Sqlite_Utility::i();
        }

    }

}
/* Eden_Amazon_Error */
if (!class_exists('Eden_Amazon_Error')) {

    class Eden_Amazon_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Amazon_Base */
if (!class_exists('Eden_Amazon_Base')) {

    class Eden_Amazon_Base extends \Eden {

        protected $_publicKey = NULL;
        protected $_privateKey = NULL;
        protected $_host = 'ecs.amazonaws.';
        protected $_uri = '/onca/xml';
        protected $_params = array();
        protected $_method = 'GET';
        protected $_canonicalizedQuery = NULL;
        protected $_stringToSign = NULL;
        protected $_signature = NULL;
        protected $_requestUrl = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($privateKey, $publicKey) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_privateKey = $privateKey;
            $this->_publicKey = $publicKey;
        }

        public function setTimestamp($time = NULL) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'int', 'null');
            if ($time == NULL) {
                $time = time();
            }if (is_string($time)) {
                $time = strtotime($time);
            }$this->_params['Timestamp'] = gmdate("Y-m-d\TH:i:s\Z", $time);
            return $this;
        }

        public function setVersion($version) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Version'] = $version;
            return $this;
        }

        protected function _sendRequest() {
            return $this->Eden_Curl()->setUrl($this->_requestUrl)->verifyHost(false)->verifyPeer(false)->setTimeout(60)->getResponse();
        }

        protected function _setSignature() {
            $this->_signature = base64_encode(hash_hmac("sha256", $this->_stringToSign, $this->_privateKey, True));
            $this->_signature = str_replace("%7E", "~", rawurlencode($this->_signature));
            return $this;
        }

        protected function _postRequest($query, $headers = array()) {
            $curl = Eden_Curl::i()->verifyHost(false)->verifyPeer(false)->setUrl('https://' . $this->_host . '/')->setPost(true)->setHeaders($headers)->setPostFields($query);
            return $curl->getResponse();
        }

    }

}
/* Eden_Amazon_Ec2 */
if (!class_exists('Eden_Amazon_Ec2')) {

    class Eden_Amazon_Ec2 extends \Eden {

        protected $_accessKey = NULL;
        protected $_accessSecret = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($accessKey, $accessSecret) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_accessKey = $accessKey;
            $this->_accessSecret = $accessSecret;
        }

        public function ami() {
            return Eden_Amazon_Ec2_Ami::i($this->_accessKey, $this->_accessSecret);
        }

        public function customerGateway() {
            return Eden_Amazon_Ec2_CustomerGateway::i($this->_accessKey, $this->_accessSecret);
        }

        public function devPay() {
            return Eden_Amazon_Ec2_Devpay::i($this->_accessKey, $this->_accessSecret);
        }

        public function dhcp() {
            return Eden_Amazon_Ec2_Dhcp::i($this->_accessKey, $this->_accessSecret);
        }

        public function elasticBookStore() {
            return Eden_Amazon_Ec2_ElasticBookStore::i($this->_accessKey, $this->_accessSecret);
        }

        public function elasticIpAddress() {
            return Eden_Amazon_Ec2_ElasticIpAddress::i($this->_accessKey, $this->_accessSecret);
        }

        public function general() {
            return Eden_Amazon_Ec2_General::i($this->_accessKey, $this->_accessSecret);
        }

        public function instances() {
            return Eden_Amazon_Ec2_Instances::i($this->_accessKey, $this->_accessSecret);
        }

        public function internetGateWay() {
            return Eden_Amazon_Ec2_InternetGateway::i($this->_accessKey, $this->_accessSecret);
        }

        public function keyPairs() {
            return Eden_Amazon_Ec2_KeyPairs::i($this->_accessKey, $this->_accessSecret);
        }

        public function monitoring() {
            return Eden_Amazon_Ec2_Monitoring::i($this->_accessKey, $this->_accessSecret);
        }

        public function networkAcl() {
            return Eden_Amazon_Ec2_NetworkAcl::i($this->_accessKey, $this->_accessSecret);
        }

        public function networkInterface() {
            return Eden_Amazon_Ec2_NetworkInterface::i($this->_accessKey, $this->_accessSecret);
        }

        public function placementGroups() {
            return Eden_Amazon_Ec2_PlacementGroups::i($this->_accessKey, $this->_accessSecret);
        }

        public function reservedInstances() {
            return Eden_Amazon_Ec2_ReservedInstances::i($this->_accessKey, $this->_accessSecret);
        }

        public function routeTables() {
            return Eden_Amazon_Ec2_RouteTables::i($this->_accessKey, $this->_accessSecret);
        }

        public function securityGroups() {
            return Eden_Amazon_Ec2_SecurityGroups::i($this->_accessKey, $this->_accessSecret);
        }

        public function spotInstances() {
            return Eden_Amazon_Ec2_SpotInstances::i($this->_accessKey, $this->_accessSecret);
        }

        public function subnets() {
            return Eden_Amazon_Ec2_Subnets::i($this->_accessKey, $this->_accessSecret);
        }

        public function tags() {
            return Eden_Amazon_Ec2_Tags::i($this->_accessKey, $this->_accessSecret);
        }

        public function virtualPrivateGateway() {
            return Eden_Amazon_Ec2_VirtualPrivateGateway::i($this->_accessKey, $this->_accessSecret);
        }

        public function vmExport() {
            return Eden_Amazon_Ec2_VmExport::i($this->_accessKey, $this->_accessSecret);
        }

        public function vmImport() {
            return Eden_Amazon_Ec2_VmImport::i($this->_accessKey, $this->_accessSecret);
        }

        public function vpnConnections() {
            return Eden_Amazon_Ec2_VpnConnections::i($this->_accessKey, $this->_accessSecret);
        }

        public function vpc() {
            return Eden_Amazon_Ec2_Vpc::i($this->_accessKey, $this->_accessSecret);
        }

        public function windows() {
            return Eden_Amazon_Ec2_Windows::i($this->_accessKey, $this->_accessSecret);
        }

    }

}
/* Eden_Amazon_Ec2_Base */
if (!class_exists('Eden_Amazon_Ec2_Base')) {

    class Eden_Amazon_Ec2_Base extends \Eden {

        const AMAZON_EC2_URL = 'https://ec2.amazonaws.com/';
        const AMAZON_EC2_HOST = 'ec2.amazonaws.com';
        const VERSION_DATE = '2012-07-20';
        const VERSION = 'Version';
        const SIGNATURE = 'Signature';
        const SIGNATURE_VERSION = 'SignatureVersion';
        const SIGNATURE_METHOD = 'SignatureMethod';
        const ACCESS_KEY = 'AWSAccessKeyId';
        const TIMESTAMP = 'Timestamp';

        protected $_meta = NULL;
        protected $_versionDate = self::VERSION_DATE;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($accessKey, $accessSecret) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_accessKey = $accessKey;
            $this->_accessSecret = $accessSecret;
        }

        public function setFilterName($filterName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Filter_Name'] [isset($this->_query['Filter_Name']) ? count($this->_query['Filter_Name']) + 1 : 1] = $filterName;
            return $this;
        }

        public function setFilterValue($filterNumber, $valueNumber, $filterValue) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'int')->argument(2, 'string', 'int')->argument(3, 'string');
            $this->_query[sprintf('Filter.%s.Value.%s', $filterNumber, $valueNumber)] = $filterValue;
            return $this;
        }

        public function getMeta() {
            return $this->_meta;
        }

        public function setVersionDate($date) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_versionDate = $date;
            return $this;
        }

        public function isXml($xml) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'array', 'object', 'null');
            if (is_array($xml) || is_null($xml)) {
                return false;
            }libxml_use_internal_errors(true);
            $doc = new DOMDocument('1.0', 'utf-8');
            $doc->loadXML($xml);
            $errors = libxml_get_errors();
            return empty($errors);
        }

        protected function _generateSignature($host, $query) {
            $signature = "GET\n";
            $signature.="$host\n";
            $signature.="/\n";
            ksort($query);
            $first = true;
            foreach ($query as $key => $value) {
                $signature.=(!$first ? '&' : '') . rawurlencode($key) . '=' . rawurlencode($value);
                $first = false;
            }$signature = hash_hmac('sha256', $signature, $this->_accessSecret, true);
            $signature = base64_encode($signature);
            return $signature;
        }

        protected function _accessKey($array) {
            foreach ($array as $key => $val) {
                if (is_array($val)) {
                    $array[$key] = $this->_accessKey($val);
                }if ($val == NULL || empty($val)) {
                    unset($array[$key]);
                }
            }return $array;
        }

        protected function _formatQuery($rawQuery) {
            foreach ($rawQuery as $key => $value) {
                if (is_array($value)) {
                    foreach ($value as $k => $v) {
                        $keyValue = explode('_', $key);
                        if (!empty($keyValue[1])) {
                            $name = rawurlencode($keyValue[0] . '.' . $k . '.' . $keyValue[1]);
                        } else {
                            $name = rawurlencode($keyValue[0] . '.' . $k);
                        }$query[str_replace("%7E", "~", $name)] = str_replace("%7E", "~", rawurlencode($v));
                    }
                } else {
                    $query[str_replace("%7E", "~", rawurlencode($key))] = str_replace("%7E", "~", rawurlencode($value));
                }
            }return $query;
        }

        protected function _getResponse($host, $rawQuery) {
            $rawQuery = $this->_accessKey($rawQuery);
            ksort($rawQuery);
            $query = $this->_formatQuery($rawQuery);
            $domain = "https://$host/";
            $query[self::ACCESS_KEY] = $this->_accessKey;
            $query[self::TIMESTAMP] = date('c');
            $query[self::VERSION] = $this->_versionDate;
            $query[self::SIGNATURE_METHOD] = 'HmacSHA256';
            $query[self::SIGNATURE_VERSION] = 2;
            $query[self::SIGNATURE] = $this->_generateSignature($host, $query);
            $url = $domain . '?' . http_build_query($query);
            $curl = Eden_Curl::i()->setUrl($url)->verifyHost(false)->verifyPeer(false)->setTimeout(60);
            $response = $curl->getResponse();
            if ($this->isXml($response)) {
                $response = simplexml_load_string($response);
            }$this->_meta['url'] = $url;
            $this->_meta['query'] = $query;
            $this->_meta['curl'] = $curl->getMeta();
            $this->_meta['response'] = $response;
            return $response;
        }

    }

}
/* Eden_Amazon_Ec2_Ami */
if (!class_exists('Eden_Amazon_Ec2_Ami')) {

    class Eden_Amazon_Ec2_Ami extends Eden_Amazon_Ec2_Base {

        const CONFIRM_PRODUCT_INSTACE = 'ConfirmProductInstance';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function registerImage($name) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'RegisterImage';
            $this->_query['Name'] = $name;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createImage($imageName, $instanceId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'CreateImage';
            $this->_query['Name'] = $imageName;
            $this->_query['InstanceId'] = $instanceId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deregisterImage($imageId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeregisterImage';
            $this->_query['ImageId'] = $ImageId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeImageAttribute($imageId, $attribute) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            if (!in_array($attribute, array('description', 'kernel', 'ramdisk', 'launchPermission', 'productCodes', 'blockDeviceMapping'))) {
                Eden_Amazon_Error::i()->setMessage(Eden_Amazon_Error::INVALID_ATTRIBUTES)->addVariable($attribute)->trigger();
            }$this->_query['Action'] = 'DescribeImageAttribute';
            $this->_query['ImageId'] = $imageId;
            $this->_query['Attribute'] = $attribute;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeImages() {
            $this->_query['Action'] = 'DescribeImages';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function modifyImageAttribute() {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'ModifyImageAttribute';
            $this->_query['ImageId'] = $imageId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setDeviceName($deviceName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['BlockDeviceMapping_DeviceName'] [isset($this->_query['BlockDeviceMapping_DeviceName']) ? count($this->_query['BlockDeviceMapping_DeviceName']) + 1 : 1] = $deviceName;
            return $this;
        }

        public function suppressDevice($supressDevice) {
            Eden_Amazon_Error::i()->argument(1, 'bool');
            $this->_query['BlockDeviceMapping_NoDevice'] [isset($this->_query['BlockDeviceMapping_NoDevice']) ? count($this->_query['BlockDeviceMapping_NoDevice']) + 1 : 1] = $supressDevice;
            return $this;
        }

        public function setVirtualName($virtualName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['BlockDeviceMapping_VirtualName'] [isset($this->_query['BlockDeviceMapping_VirtualName']) ? count($this->_query['BlockDeviceMapping_VirtualName']) + 1 : 1] = $virtualName;
            return $this;
        }

        public function setSnapshotId($snapshotId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['BlockDeviceMapping_Ebs.SnapshotId'] [isset($this->_query['BlockDeviceMapping_Ebs.SnapshotId']) ? count($this->_query['BlockDeviceMapping_Ebs.SnapshotId']) + 1 : 1] = $snapshotId;
            return $this;
        }

        public function setVolumeSize($volumeSize) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'int');
            $this->_query['BlockDeviceMapping_Ebs.VolumeSize'] [isset($this->_query['BlockDeviceMapping_Ebs.VolumeSize']) ? count($this->_query['BlockDeviceMapping_Ebs.VolumeSize']) + 1 : 1] = $volumeSize;
            return $this;
        }

        public function deleteOnTermination($deleteOnTermination) {
            Eden_Amazon_Error::i()->argument(1, 'bool');
            $this->_query['BlockDeviceMapping_Ebs.DeleteOnTermination'] [isset($this->_query['BlockDeviceMapping_Ebs.DeleteOnTermination']) ? count($this->_query['BlockDeviceMapping_Ebs.DeleteOnTermination']) + 1 : 1] = $deleteOnTermination;
            return $this;
        }

        public function setVolumeType($volumeType) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['BlockDeviceMapping_Ebs.VolumeType'] [isset($this->_query['BlockDeviceMapping_Ebs.VolumeType']) ? count($this->_query['BlockDeviceMapping_Ebs.VolumeType']) + 1 : 1] = $volumeType;
            return $this;
        }

        public function setIops($iops) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'integer');
            $this->_query['BlockDeviceMapping_Ebs.Iops'] [isset($this->_query['BlockDeviceMapping_Ebs.Iops']) ? count($this->_query['BlockDeviceMapping_Ebs.Iops']) + 1 : 1] = $iops;
            return $this;
        }

        public function setPermission($permission) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ExecutableBy'] [isset($this->_query['ExecutableBy']) ? count($this->_query['ExecutableBy']) + 1 : 1] = $permission;
            return $this;
        }

        public function setImageId($imageId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ImageId'] [isset($this->_query['ImageId']) ? count($this->_query['ImageId']) + 1 : 1] = $imageId;
            return $this;
        }

        public function setOwner($owner) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Owner'] [isset($this->_query['Owner']) ? count($this->_query['Owner']) + 1 : 1] = $owner;
            return $this;
        }

        public function setImageLocation($imageLocation) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ImageLocation'] = $imageLocation;
            return $this;
        }

        public function setDescription($description) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Description'] = $description;
            return $this;
        }

        public function setArchitecture($architecture) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Architecture'] = $architecture;
            return $this;
        }

        public function setKernelId($kernelId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['KernelId'] = $kernelId;
            return $this;
        }

        public function setRamdiskId($ramdiskId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['RamdiskId'] = $ramdiskId;
            return $this;
        }

        public function setRootDeviceName($rootDeviceName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['RootDeviceName'] = $rootDeviceName;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_CustomerGateway */
if (!class_exists('Eden_Amazon_Ec2_CustomerGateway')) {

    class Eden_Amazon_Ec2_CustomerGateway extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createCustomerGateway($type, $ipAddress, $bgpAsn) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query['Action'] = 'CreateCustomerGateway';
            $this->_query['Type'] = $type;
            $this->_query['IpAddress'] = $ipAddress;
            $this->_query['BgpAsn'] = $bgpAsn;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteCustomerGateway($customerGatewayId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteCustomerGateway';
            $this->_query['CustomerGatewayId'] = $customerGatewayId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeCustomerGateway() {
            $this->_query['Action'] = 'DescribeCustomerGateways';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setCustomerGatewayId($customerGatewayId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['CustomerGatewayId'] [isset($this->_query['CustomerGatewayId']) ? count($this->_query['CustomerGatewayId']) + 1 : 1] = $customerGatewayId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_Devpay */
if (!class_exists('Eden_Amazon_Ec2_Devpay')) {

    class Eden_Amazon_Ec2_Devpay extends Eden_Amazon_Ec2_Base {

        const CONFIRM_PRODUCT_INSTACE = 'ConfirmProductInstance';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function confirmProductInstance($productCode, $instanceId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = array('Action' => self::CONFIRM_PRODUCT_INSTACE, 'ProductCode' => $productCode, 'InstanceId' => $instanceId);
            return $this->_getResponse(self::AMAZON_EC2_HOST, $query);
        }

    }

}
/* Eden_Amazon_Ec2_Dhcp */
if (!class_exists('Eden_Amazon_Ec2_Dhcp')) {

    class Eden_Amazon_Ec2_Dhcp extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function associateDhcpOptions($dhcpOptionsId, $vpcId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'AssociateDhcpOptions ';
            $this->_query['DhcpOptionsId'] = $dhcpOptionsId;
            $this->_query['VpcId'] = $vpcId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createDhcpOptions() {
            $this->_query['Action'] = 'CreateDhcpOptions';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteDhcpOptions($dhcpOptionsId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteDhcpOptions';
            $this->_query['DhcpOptionsId'] = $dhcpOptionsId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setDhcpConfigurationKey($key) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['DhcpConfiguration_Key'] [isset($this->_query['DhcpConfiguration_Key']) ? count($this->_query['DhcpConfiguration_Key']) + 1 : 1] = $key;
            return $this;
        }

        public function setDhcpConfigurationValue($value) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['DhcpConfiguration_Value_'] [isset($this->_query['DhcpConfiguration_Value_']) ? count($this->_query['DhcpConfiguration_Value_']) + 1 : 1] = $value;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_ElasticBookStore */
if (!class_exists('Eden_Amazon_Ec2_ElasticBookStore')) {

    class Eden_Amazon_Ec2_ElasticBookStore extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function attachVolume($volumeId, $instanceId, $device) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query['Action'] = 'AttachVolume';
            $this->_query['VolumeId'] = $volumeId;
            $this->_query['InstanceId'] = $instanceId;
            $this->_query['Device'] = $device;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createSnapShot($volumeId, $description) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'CreateSnapshot';
            $this->_query['VolumeId'] = $volumeId;
            $this->_query['Description'] = $description;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createVolume($availabilityZone) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CreateVolume';
            $this->_query['AvailabilityZone'] = $availabilityZone;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteSnapshot($snapshotId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteSnapshot';
            $this->_query['SnapshotId'] = $snapshotId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteVolume($volumeId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteSnapshot';
            $this->_query['VolumeId'] = $volumeId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeSnapshotAttribute($snapshotId, $attribute) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'DescribeSnapshotAttribute';
            $this->_query['SnapshotId'] = $snapshotId;
            $this->_query['Attribute'] = $attribute;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeSnapshots() {
            $this->_query['Action'] = 'DescribeSnapshots';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeVolumes() {
            $this->_query['Action'] = 'DescribeVolumes';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeVolumeAttribute($volumeId, $attribute) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'DescribeVolumeAttribute';
            $this->_query['VolumeId'] = $volumeId;
            $this->_query['Attribute'] = $attribute;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeVolumeStatus() {
            $this->_query['Action'] = 'DescribeVolumeStatus';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function detachVolume($volumeId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DetachVolume';
            $this->_query['VolumeId'] = $volumeId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function enableVolumeIO($volumeId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'EnableVolumeIO';
            $this->_query['VolumeId'] = $volumeId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function importVolume($imageFormat, $imageBytes, $url, $volumeSize) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'int');
            $this->_query['Action'] = 'ImportVolume';
            $this->_query['Image.Format'] = $imageFormat;
            $this->_query['Image.Bytes'] = $imageBytes;
            $this->_query['Image.ImportManifestUrl'] = $url;
            $this->_query['Volume.Size'] = $volumeSize;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function modifyVolumeAttribute($volumeId, $autoEnableIO = false) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'bool');
            $this->_query['Action'] = 'ModifyVolumeAttribute';
            $this->_query['VolumeId'] = $imageFormat;
            $this->_query['AutoEnableIO.Value'] = $autoEnableIO;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function resetSnapshotAttribute($snapshotId, $attribute) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'ResetSnapshotAttribute';
            $this->_query['SnapshotId'] = $snapshotId;
            $this->_query['Attribute'] = $attribute;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setSize($size) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Size'] = $size;
            return $this;
        }

        public function setSnapshotId($snapshotId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['SnapshotId'] = $snapshotId;
            return $this;
        }

        public function setVolumeType($volumeType) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['VolumeType'] = $volumeType;
            return $this;
        }

        public function setIops($iops) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Iops'] = $iops;
            return $this;
        }

        public function setSnapshotsId($snapshotId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['SnapshotId_'] [isset($this->_query['SnapshotId_']) ? count($this->_query['SnapshotId_']) + 1 : 1] = $snapshotId;
            return $this;
        }

        public function setOwner($owner) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Owner_'] [isset($this->_query['Owner_']) ? count($this->_query['Owner_']) + 1 : 1] = $owner;
            return $this;
        }

        public function restorableBy($accountId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['RestorableBy_'] [isset($this->_query['RestorableBy_']) ? count($this->_query['RestorableBy_']) + 1 : 1] = $accountId;
            return $this;
        }

        public function setVolumeId($volumeId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['VolumeId_'] [isset($this->_query['VolumeId_']) ? count($this->_query['VolumeId_']) + 1 : 1] = $volumeId;
            return $this;
        }

        public function setMaxResults($maxResults) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_query['MaxResults'] = $maxResults;
            return $this;
        }

        public function setNextToken($nextToken) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NextToken'] = $nextToken;
            return $this;
        }

        public function setInstanceId($instanceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['InstanceId'] = $instanceId;
            return $this;
        }

        public function setDevice($device) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Device'] = $device;
            return $this;
        }

        public function userForce() {
            $this->_query['Force'] = true;
            return $this;
        }

        public function setAvailabilityZone($availabilityZone) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['AvailabilityZone'] = $availabilityZone;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_ElasticIpAddress */
if (!class_exists('Eden_Amazon_Ec2_ElasticIpAddress')) {

    class Eden_Amazon_Ec2_ElasticIpAddress extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function allocateAddress() {
            $this->_query['Action'] = 'AllocateAddress';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function associateAddress() {
            $this->_query['Action'] = 'AssociateAddress';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeAddresses() {
            $this->_query['Action'] = 'DescribeAddresses';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function disassociateAddress() {
            $this->_query['Action'] = 'DisassociateAddress';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function releaseAddress() {
            $this->_query['Action'] = 'ReleaseAddress';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setDomain() {
            $this->_query['Domain'] = 'vpc';
            return $this;
        }

        public function setPublicIp($publicIp) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['PublicIp'] = $publicIp;
            return $this;
        }

        public function setInstanceId($instanceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['InstanceId'] = $instanceId;
            return $this;
        }

        public function setAllocationId($allocationId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['AllocationId'] = $allocationId;
            return $this;
        }

        public function setNetworkInterfaceId($networkInterfaceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NetworkInterfaceId'] = $networkInterfaceId;
            return $this;
        }

        public function setPrivateIpAddress($privateIpAddress) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['PrivateIpAddress'] = $privateIpAddress;
            return $this;
        }

        public function setAllowReassociation($allowReassociation) {
            Eden_Amazon_Error::i()->argument(1, 'bool');
            $this->_query['AllowReassociation'] = $allowReassociation;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_General */
if (!class_exists('Eden_Amazon_Ec2_General')) {

    class Eden_Amazon_Ec2_General extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getConsoleOutput($instanceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'GetConsoleOutput';
            $this->_query['InstanceId'] = $instanceId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

    }

}
/* Eden_Amazon_Ec2_Instances */
if (!class_exists('Eden_Amazon_Ec2_Instances')) {

    class Eden_Amazon_Ec2_Instances extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function describeInstanceAttribute($instanceId, $attribute) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'DescribeInstanceAttribute';
            $this->_query['InstanceId'] = $instanceId;
            $this->_query['Attribute'] = $attribute;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeInstances() {
            $this->_query['Action'] = 'DescribeInstances';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeInstanceStatus() {
            $this->_query['Action'] = 'DescribeInstanceStatus';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function rebootInstances() {
            $this->_query['Action'] = 'RebootInstances';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function reportInstanceStatus() {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'ReportInstanceStatus';
            $this->_query['Status'] = $status;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function resetInstanceAttribute($instanceId, $attribute) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'ResetInstanceAttribute';
            $this->_query['InstanceId'] = $instanceId;
            $this->_query['Attribute'] = $attribute;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function runInstances($instanceId, $attribute) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(1, 'int')->argument(2, 'int');
            $this->_query['Action'] = 'RunInstances';
            $this->_query['ImageId'] = $imageId;
            $this->_query['MinCount'] = $minCount;
            $this->_query['MaxCount'] = $maxCount;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function startInstances() {
            $this->_query['Action'] = 'StartInstances';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setInstanceId($instanceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['InstanceId_'] [isset($this->_query['InstanceId_']) ? count($this->_query['InstanceId_']) + 1 : 1] = $instanceId;
            return $this;
        }

        public function setReasonCodes($reasonCodes) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ReasonCodes_'] [isset($this->_query['ReasonCodes_']) ? count($this->_query['ReasonCodes_']) + 1 : 1] = $reasonCodes;
            return $this;
        }

        public function setStatus($status) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Status'] = $status;
            return $this;
        }

        public function setStartTime($startTime) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['StartTime'] = $startTime;
            return $this;
        }

        public function setEndTime($endTime) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['EndTime'] = $endTime;
            return $this;
        }

        public function setDescription($description) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Description'] = $description;
            return $this;
        }

        public function setKeyName($keyName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['KeyName'] = $keyName;
            return $this;
        }

        public function setSecurityGroupId($securityGroupId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['SecurityGroupId_'] [isset($this->_query['SecurityGroupId_']) ? count($this->_query['SecurityGroupId_']) + 1 : 1] = $securityGroupId;
            return $this;
        }

        public function setSecurityGroup($securityGroup) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['SecurityGroup_'] [isset($this->_query['SecurityGroup_']) ? count($this->_query['SecurityGroup_']) + 1 : 1] = $securityGroup;
            return $this;
        }

        public function setUserData($userData) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['UserData'] = base64_encode($userData);
            return $this;
        }

        public function setInstanceType($InstanceType) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['InstanceType'] = $instanceType;
            return $this;
        }

        public function setAvailabilityZone($availabilityZone) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Placement.AvailabilityZone'] = $availabilityZone;
            return $this;
        }

        public function setGroupName($groupName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Placement.GroupName'] = $groupName;
            return $this;
        }

        public function setTenancy($tenancy) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Placement.Tenancy'] = $tenancy;
            return $this;
        }

        public function setKernelId($kernelId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['KernelId'] = $kernelId;
            return $this;
        }

        public function setRamdiskId($ramdiskId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['RamdiskId'] = $ramdiskId;
            return $this;
        }

        public function setDeviceName($deviceName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['BlockDeviceMapping_DeviceName'] [isset($this->_query['BlockDeviceMapping_DeviceName']) ? count($this->_query['BlockDeviceMapping_DeviceName']) + 1 : 1] = $deviceName;
            return $this;
        }

        public function setNoDevice($noDevice) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['BlockDeviceMapping_NoDevice'] [isset($this->_query['BlockDeviceMapping_NoDevice']) ? count($this->_query['BlockDeviceMapping_NoDevice']) + 1 : 1] = $noDevice;
            return $this;
        }

        public function setVirtualName($virtualName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['BlockDeviceMapping_VirtualName'] [isset($this->_query['BlockDeviceMapping_VirtualName']) ? count($this->_query['BlockDeviceMapping_VirtualName']) + 1 : 1] = $virtualName;
            return $this;
        }

        public function enableMonitoring() {
            $this->_query['Monitoring.Enabled'] = true;
            return $this;
        }

        public function disableApiTermination() {
            $this->_query['DisableApiTermination'] = true;
            return $this;
        }

        public function setSubnetId($subnetId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['SubnetId'] = $subnetId;
            return $this;
        }

        public function terminateInstance() {
            $this->_query['InstanceInitiatedShutdownBehavior'] = 'terminate	';
            return $this;
        }

        public function setPrivateIpAddress($privateIpAddress) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['PrivateIpAddress'] = $privateIpAddress;
            return $this;
        }

        public function setClientToken($clientToken) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ClientToken'] = $clientToken;
            return $this;
        }

        public function setNetworkInterfaceId($networkInterfaceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NetworkInterface_NetworkInterfaceId'] [isset($this->_query['NetworkInterface_NetworkInterfaceId']) ? count($this->_query['NetworkInterface_NetworkInterfaceId']) + 1 : 1] = $networkInterfaceId;
            return $this;
        }

        public function setDeviceIndex($deviceIndex) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NetworkInterface_DeviceIndex'] [isset($this->_query['NetworkInterface_DeviceIndex']) ? count($this->_query['NetworkInterface_DeviceIndex']) + 1 : 1] = $deviceIndex;
            return $this;
        }

        public function setSubnetIds($subnetId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NetworkInterface_SubnetId'] [isset($this->_query['NetworkInterface_SubnetId']) ? count($this->_query['NetworkInterface_SubnetId']) + 1 : 1] = $subnetId;
            return $this;
        }

        public function setDescriptions($description) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NetworkInterface_Description'] [isset($this->_query['NetworkInterface_Description']) ? count($this->_query['NetworkInterface_Description']) + 1 : 1] = $description;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_InternetGateway */
if (!class_exists('Eden_Amazon_Ec2_InternetGateway')) {

    class Eden_Amazon_Ec2_InternetGateway extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function attachInternetGateway($internetGatewayId, $vpcId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'AttachInternetGateway';
            $this->_query['InternetGatewayId'] = $internetGatewayId;
            $this->_query['VpcId'] = $vpcId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createInternetGateway() {
            $this->_query['Action'] = 'CreateInternetGateway';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteInternetGateway($internetGatewayId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteInternetGateway';
            $this->_query['InternetGatewayId'] = $internetGatewayId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeInternetGateways() {
            $this->_query['Action'] = 'DescribeInternetGateways';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function detachInternetGateway($vpcId, $internetGatewayId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'DetachInternetGateway';
            $this->_query['VpcId'] = $vpcId;
            $this->_query['InternetGatewayId'] = $internetGatewayId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setInternetGatewayId($internetGatewayId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['InternetGatewayId_'] [isset($this->_query['InternetGatewayId_']) ? count($this->_query['InternetGatewayId_']) + 1 : 1] = $internetGatewayId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_KeyPairs */
if (!class_exists('Eden_Amazon_Ec2_KeyPairs')) {

    class Eden_Amazon_Ec2_KeyPairs extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createKeyPair($keyName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CreateKeyPair';
            $this->_query['KeyName'] = $keyName;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteKeyPair($keyName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteKeyPair';
            $this->_query['KeyName'] = $keyName;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeKeyPairs() {
            $this->_query['Action'] = 'DescribeKeyPairs';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function importKeyPair($keyName, $publicKeyMaterial) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'ImportKeyPair';
            $this->_query['KeyName'] = $keyName;
            $this->_query['PublicKeyMaterial'] = base64_encode($publicKeyMaterial);
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setKeyName($keyName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['KeyName_'] [isset($this->_query['KeyName_']) ? count($this->_query['KeyName_']) + 1 : 1] = $keyName;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_Monitoring */
if (!class_exists('Eden_Amazon_Ec2_Monitoring')) {

    class Eden_Amazon_Ec2_Monitoring extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function monitorInstances() {
            $this->_query['Action'] = 'MonitorInstances';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function unmonitorInstances() {
            $this->_query['Action'] = 'UnmonitorInstances';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setInstanceId($instanceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['InstanceId_'] [isset($this->_query['InstanceId_']) ? count($this->_query['InstanceId_']) + 1 : 1] = $instanceId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_NetworkAcl */
if (!class_exists('Eden_Amazon_Ec2_NetworkAcl')) {

    class Eden_Amazon_Ec2_NetworkAcl extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createNetworkAcl($VpcId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CreateNetworkAcl';
            $this->_query['VpcId'] = $vpcId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createNetworkAclEntry($networkAclId, $ruleNumber, $protocol, $ruleAction, $cidrBlock) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'int')->argument(3, 'int')->argument(4, 'string')->argument(5, 'string');
            $this->_query['Action'] = 'CreateNetworkAclEntry';
            $this->_query['NetworkAclId'] = $networkAclId;
            $this->_query['RuleNumber'] = $ruleNumber;
            $this->_query['Protocol'] = $protocol;
            $this->_query['RuleAction'] = $ruleAction;
            $this->_query['CidrBlock'] = $cidrBlock;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteNetworkAcl($networkAclId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteNetworkAcl';
            $this->_query['NetworkAclId'] = $networkAclId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteNetworkAclEntry($networkAclId, $ruleNumber) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'int');
            $this->_query['Action'] = 'DeleteNetworkAclEntry';
            $this->_query['NetworkAclId'] = $networkAclId;
            $this->_query['RuleNumber'] = $ruleNumber;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeNetworkAcls() {
            $this->_query['Action'] = 'DescribeNetworkAcls';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function replaceNetworkAclAssociation($networkAclId, $associationId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'ReplaceNetworkAclAssociation';
            $this->_query['NetworkAclId'] = $networkAclId;
            $this->_query['AssociationId'] = $associationId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function replaceNetworkAclEntry($networkAclId, $ruleNumber, $protocol, $ruleAction, $cidrBlock) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'int')->argument(3, 'int')->argument(4, 'string')->argument(5, 'string');
            $this->_query['Action'] = 'ReplaceNetworkAclEntry';
            $this->_query['NetworkAclId'] = $networkAclId;
            $this->_query['RuleNumber'] = $ruleNumber;
            $this->_query['Protocol'] = $protocol;
            $this->_query['RuleAction'] = $ruleAction;
            $this->_query['CidrBlock'] = $cidrBlock;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setEgress($egress) {
            Eden_Amazon_Error::i()->argument(1, 'bool');
            $this->_query['Egress'] = $egress;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setIcmpCode($code) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_query['Icmp.Code'] = $code;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setIcmpType($code) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_query['Icmp.Type'] = $code;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setPortRangeFrom($firstPort) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_query['PortRange.From'] = $firstPort;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setPortRangeTo($lastPort) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_query['PortRange.To'] = $lastPort;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setNetworkAclId($networkAclId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NetworkAclId_'] [isset($this->_query['NetworkAclId_']) ? count($this->_query['NetworkAclId_']) + 1 : 1] = $networkAclId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_NetworkInterface */
if (!class_exists('Eden_Amazon_Ec2_NetworkInterface')) {

    class Eden_Amazon_Ec2_NetworkInterface extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function attachNetworkInterface($networkInterfaceId, $instanceId, $deviceIndex) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query['Action'] = 'AttachNetworkInterface';
            $this->_query['NetworkInterfaceId'] = $networkInterfaceId;
            $this->_query['InstanceId'] = $instanceId;
            $this->_query['DeviceIndex'] = $deviceIndex;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function detachNetworkInterface($attachmentId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DetachNetworkInterface';
            $this->_query['AttachmentId'] = $attachmentId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createNetworkInterface($subnetId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CreateNetworkInterface';
            $this->_query['SubnetId'] = $subnetId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteNetworkInterface($networkInterfaceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteNetworkInterface';
            $this->_query['NetworkInterfaceId'] = $networkInterfaceId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeNetworkInterfaces($networkInterfaceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DescribeNetworkInterfaces';
            $this->_query['NetworkInterfaceId'] = $networkInterfaceId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeNetworkInterfaceAttribute($networkInterfaceId, $attribute) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'DescribeNetworkInterfaceAttribute';
            $this->_query['NetworkInterfaceId'] = $networkInterfaceId;
            $this->_query['Attribute'] = $attribute;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function resetNetworkInterfaceAttribute($networkInterfaceId, $attribute) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'ResetNetworkInterfaceAttribute';
            $this->_query['NetworkInterfaceId'] = $networkInterfaceId;
            $this->_query['Attribute'] = $attribute;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function forceDetachment() {
            $this->_query['Force'] = true;
            return $this;
        }

        public function setPrivateIpAddress($privateIpAddress) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['PrivateIpAddress	'] = $privateIpAddress;
            return $this;
        }

        public function setPrivateIpAddresses($privateIpAddresses) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['PrivateIpAddresses_PrivateIpAddress'] [isset($this->_query['PrivateIpAddresses_PrivateIpAddress']) ? count($this->_query['PrivateIpAddresses_PrivateIpAddress']) + 1 : 1] = $privateIpAddresses;
            return $this;
        }

        public function setPrimaryPrivateIpAddress($primaryPrivateIpAddress) {
            Eden_Amazon_Error::i()->argument(1, 'bool');
            $this->_query['PrivateIpAddresses_Primary'] [isset($this->_query['PrivateIpAddresses_Primary']) ? count($this->_query['PrivateIpAddresses_Primary']) + 1 : 1] = $primaryPrivateIpAddress;
            return $this;
        }

        public function setSecondaryPrivateIpAddressCount($secondaryPrivateIpAddressCount) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_query['SecondaryPrivateIpAddressCount'] = $secondaryPrivateIpAddressCount;
            return $this;
        }

        public function setDescription($description) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Description'] = $description;
            return $this;
        }

        public function setSecurityGroupId($securityGroupId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['SecurityGroupId_'] [isset($this->_query['SecurityGroupId_']) ? count($this->_query['SecurityGroupId_']) + 1 : 1] = $securityGroupId;
            return $this;
        }

        public function setNetworkInterfaceId($networkInterfaceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NetworkInterfaceId_'] [isset($this->_query['NetworkInterfaceId_']) ? count($this->_query['NetworkInterfaceId_']) + 1 : 1] = $networkInterfaceId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_PlacementGroups */
if (!class_exists('Eden_Amazon_Ec2_PlacementGroups')) {

    class Eden_Amazon_Ec2_PlacementGroups extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createPlacementGroup($groupName, $strategy) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'CreatePlacementGroup';
            $this->_query['GroupName'] = $groupName;
            $this->_query['Strategy'] = $strategy;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deletePlacementGroup($groupName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeletePlacementGroup';
            $this->_query['GroupName'] = $groupName;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describePlacementGroups() {
            $this->_query['Action'] = 'DescribePlacementGroups';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setGroupName($groupName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['GroupName_'] [isset($this->_query['GroupName_']) ? count($this->_query['GroupName_']) + 1 : 1] = $groupName;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_ReservedInstances */
if (!class_exists('Eden_Amazon_Ec2_ReservedInstances')) {

    class Eden_Amazon_Ec2_ReservedInstances extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function DescribeReservedInstances() {
            $this->_query['Action'] = 'DescribeReservedInstances';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeReservedInstancesOfferings() {
            $this->_query['Action'] = 'DescribeReservedInstancesOfferings';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function purchaseReservedInstancesOffering($reservedInstancesOfferingId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'PurchaseReservedInstancesOffering';
            $this->_query['ReservedInstancesOfferingId'] = $reservedInstancesOfferingId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setReservedInstancesId($reservedInstancesId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ReservedInstancesId_'] [isset($this->_query['ReservedInstancesId_']) ? count($this->_query['ReservedInstancesId_']) + 1 : 1] = $reservedInstancesId;
            return $this;
        }

        public function setOfferingType($offeringType) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['offeringType'] = $offeringType;
            return $this;
        }

        public function setReservedInstancesOfferingId($reservedInstancesOfferingId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ReservedInstancesOfferingId_'] [isset($this->_query['ReservedInstancesOfferingId_']) ? count($this->_query['ReservedInstancesOfferingId_']) + 1 : 1] = $reservedInstancesOfferingId;
            return $this;
        }

        public function setInstanceType($instanceType) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['InstanceType'] = $instanceType;
            return $this;
        }

        public function setAvailabilityZone($availabilityZone) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['AvailabilityZone'] = $availabilityZone;
            return $this;
        }

        public function setProductDescription($productDescription) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ProductDescription'] = $productDescription;
            return $this;
        }

        public function setInstanceTenancy($instanceTenancy) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['instanceTenancy'] = $instanceTenancy;
            return $this;
        }

        public function setInstanceCount($instanceCount) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_query['InstanceCount'] = $instanceCount;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_RouteTables */
if (!class_exists('Eden_Amazon_Ec2_RouteTables')) {

    class Eden_Amazon_Ec2_RouteTables extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function associateRouteTable($routeTableId, $subnetId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'AssociateRouteTable';
            $this->_query['RouteTableId'] = $routeTableId;
            $this->_query['SubnetId'] = $subnetId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createRoute($routeTableId, $destinationCidrBlock) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'CreateRoute';
            $this->_query['RouteTableId'] = $routeTableId;
            $this->_query['DestinationCidrBlock'] = $destinationCidrBlock;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createRouteTable($vpcId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CreateRouteTable';
            $this->_query['VpcId'] = $vpcId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteRoute($routeTableId, $destinationCidrBlock) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'DeleteRoute';
            $this->_query['RouteTableId'] = $routeTableId;
            $this->_query['DestinationCidrBlock'] = $destinationCidrBlock;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteRouteTable($routeTableId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteRouteTable';
            $this->_query['RouteTableId'] = $routeTableId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeRouteTables() {
            $this->_query['Action'] = 'DescribeRouteTables';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function disassociateRouteTable($associationId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DisassociateRouteTable';
            $this->_query['AssociationId'] = $associationId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function replaceRoute($routeTableId, $destinationCidrBlock) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'ReplaceRoute';
            $this->_query['RouteTableId'] = $routeTableId;
            $this->_query['DestinationCidrBlock'] = $destinationCidrBlock;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function replaceRouteTableAssociation($routeTableId, $associationId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'ReplaceRouteTableAssociation';
            $this->_query['RouteTableId'] = $routeTableId;
            $this->_query['AssociationId'] = $associationId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setGatewayId($gatewayId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['GatewayId'] = $gatewayId;
            return $this;
        }

        public function setInstanceId($instanceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['InstanceId'] = $instanceId;
            return $this;
        }

        public function setNetworkInterfaceId($networkInterfaceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NetworkInterfaceId'] = $networkInterfaceId;
            return $this;
        }

        public function setRouteTableId($routeTableId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['RouteTableId_'] [isset($this->_query['RouteTableId_']) ? count($this->_query['RouteTableId_']) + 1 : 1] = $routeTableId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_SecurityGroups */
if (!class_exists('Eden_Amazon_Ec2_SecurityGroups')) {

    class Eden_Amazon_Ec2_SecurityGroups extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function authorizeSecurityGroupEgress($groupId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'AuthorizeSecurityGroupEgress';
            $this->_query['GroupId'] = $groupId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createSecurityGroup($groupId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'CreateSecurityGroup';
            $this->_query['GroupName'] = $groupName;
            $this->_query['GroupDescription'] = $groupDescription;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteSecurityGroup($securityGroup) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'int');
            if (is_int($securityGroup)) {
                $this->_query['GroupId'] = $securityGroup;
            } else {
                $this->_query['GroupName'] = $securityGroup;
            }$this->_query['Action'] = 'DeleteSecurityGroup';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeSecurityGroups() {
            $this->_query['Action'] = 'DescribeSecurityGroups';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function revokeSecurityGroupEgress($groupId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'RevokeSecurityGroupEgress';
            $this->_query['GroupId'] = $groupId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setGroupId($groupId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['GroupId'] = $groupId;
            return $this;
        }

        public function setGroupIds($groupIds) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['GroupId_'] [isset($this->_query['GroupId_']) ? count($this->_query['GroupId_']) + 1 : 1] = $groupIds;
            return $this;
        }

        public function setVpcId($vpcId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['VpcId'] = $vpcId;
            return $this;
        }

        public function setGroupName($groupName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['GroupName'] = $groupName;
            return $this;
        }

        public function setGroupNames($groupNames) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['GroupName_'] [isset($this->_query['GroupName_']) ? count($this->_query['GroupName_']) + 1 : 1] = $groupNames;
            return $this;
        }

        public function setIpPermissionsIpProtocol($ipProtocol) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['IpPermissions_IpProtocol'] [isset($this->_query['IpPermissions_IpProtocol']) ? count($this->_query['IpPermissions_IpProtocol']) + 1 : 1] = $ipProtocol;
            return $this;
        }

        public function setIpPermissionsFromPort($ip) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_query['IpPermissions_FromPort'] [isset($this->_query['IpPermissions_FromPort']) ? count($this->_query['IpPermissions_FromPort']) + 1 : 1] = $ip;
            return $this;
        }

        public function setIpPermissionsToPort($ip) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_query['IpPermissions_ToPort'] [isset($this->_query['IpPermissions_ToPort']) ? count($this->_query['IpPermissions_ToPort']) + 1 : 1] = $ip;
            return $this;
        }

        public function setIpPermissionsGroupId($groupId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['IpPermissions_Groups_GroupId'] [isset($this->_query['IpPermissions_Groups_GroupId']) ? count($this->_query['IpPermissions_Groups_GroupId']) + 1 : 1] = $groupId;
            return $this;
        }

        public function setIpPermissionsUserId($userId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['IpPermissions_Groups_UserId'] [isset($this->_query['IpPermissions_Groups_UserId']) ? count($this->_query['IpPermissions_Groups_UserId']) + 1 : 1] = $userId;
            return $this;
        }

        public function setIpPermissionsGroupName($groupName) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['IpPermissions_Groups_GroupName'] [isset($this->_query['IpPermissions_Groups_GroupName']) ? count($this->_query['IpPermissions_Groups_GroupName']) + 1 : 1] = $groupName;
            return $this;
        }

        public function setIpPermissionsCidrIp($cidrIp) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['IpPermissions_IpRanges_CidrIp'] [isset($this->_query['IpPermissions_IpRanges_CidrIp']) ? count($this->_query['IpPermissions_IpRanges_CidrIp']) + 1 : 1] = $cidrIp;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_SpotInstances */
if (!class_exists('Eden_Amazon_Ec2_SpotInstances')) {

    class Eden_Amazon_Ec2_SpotInstances extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function cancelSpotInstanceRequests() {
            $this->_query['Action'] = 'CancelSpotInstanceRequests';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createSpotDatafeedSubscription($bucket) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CreateSpotDatafeedSubscription';
            $this->_query['Bucket'] = $bucket;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteSpotDatafeedSubscription() {
            $this->_query['Action'] = 'DeleteSpotDatafeedSubscription';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeSpotInstanceRequests() {
            $this->_query['Action'] = 'DescribeSpotInstanceRequests';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeSpotPriceHistory() {
            $this->_query['Action'] = 'DescribeSpotPriceHistory';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setSpotInstanceRequestIds($spotInstanceRequestId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['SpotInstanceRequestId_'] [isset($this->_query['GrouSpotInstanceRequestId_pId_']) ? count($this->_query['SpotInstanceRequestId_']) + 1 : 1] = $spotInstanceRequestId;
            return $this;
        }

        public function setSpotInstanceRequestId($prefix) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Prefix'] = $prefix;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_Subnets */
if (!class_exists('Eden_Amazon_Ec2_Subnets')) {

    class Eden_Amazon_Ec2_Subnets extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createSubnet($vpcId, $cidrBlock) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'CreateSubnet';
            $this->_query['VpcId'] = $vpcId;
            $this->_query['CidrBlock'] = $cidrBlock;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteSubnet($subnetId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteSubnet';
            $this->_query['SubnetId'] = $subnetId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeSubnets() {
            $this->_query['Action'] = 'DescribeSubnets';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setTimeZone($timeZone) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['AvailabilityZone'] = $timeZone;
            return $this;
        }

        public function setSubnetId($subnetId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['SubnetId_'] [isset($this->_query['SubnetId_']) ? count($this->_query['SubnetId_']) + 1 : 1] = $subnetId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_Tags */
if (!class_exists('Eden_Amazon_Ec2_Tags')) {

    class Eden_Amazon_Ec2_Tags extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createTags() {
            $this->_query['Action'] = 'CreateTags';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteTags() {
            $this->_query['Action'] = 'DeleteTags';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeTags() {
            $this->_query['Action'] = 'DescribeTags';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setTagKey($tagKey) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Tag_Key'] [isset($this->_query['Tag_Key']) ? count($this->_query['Tag_Key']) + 1 : 1] = $tagKey;
            return $this;
        }

        public function setTagValue($tagValue) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Tag_Value'] [isset($this->_query['Tag_Value']) ? count($this->_query['Tag_Value']) + 1 : 1] = $tagValue;
            return $this;
        }

        public function setResourceId($resourceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ResourceId_'] [isset($this->_query['ResourceId_']) ? count($this->_query['ResourceId_']) + 1 : 1] = $resourceId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_VirtualPrivateGateways */
if (!class_exists('Eden_Amazon_Ec2_VirtualPrivateGateways')) {

    class Eden_Amazon_Ec2_VirtualPrivateGateways extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function attachVpnGateway($vpnGatewayId, $vpcId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'AttachVpnGateway';
            $this->_query['VpnGatewayId'] = $vpnGatewayId;
            $this->_query['VpcId'] = $vpcId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createVpnGateway($type) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CreateVpnGateway';
            $this->_query['Type'] = $type;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteVpnGateway($vpnGatewayId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteVpnGateway';
            $this->_query['VpnGatewayId'] = $vpnGatewayId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeVpnGateways($vpnGatewayId) {
            $this->_query['Action'] = 'DescribeVpnGateways';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function detachVpnGateway($vpnGatewayId, $vpcId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'DetachVpnGateway';
            $this->_query['VpnGatewayId'] = $vpnGatewayId;
            $this->_query['VpcId'] = $vpcId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setVpnGatewayId($vpnGatewayId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['VpnGatewayId_'] [isset($this->_query['VpnGatewayId_']) ? count($this->_query['VpnGatewayId_']) + 1 : 1] = $vpnGatewayId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_VmExport */
if (!class_exists('Eden_Amazon_Ec2_VmExport')) {

    class Eden_Amazon_Ec2_VmExport extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function cancelExportTask($exportTaskId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CancelExportTask';
            $this->_query['ExportTaskId'] = $exportTaskId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function createInstanceExportTask($instanceId, $targetEnvironment, $s3Bucket) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query['Action'] = 'CreateInstanceExportTask';
            $this->_query['InstanceId'] = $instanceId;
            $this->_query['TargetEnvironment'] = $targetEnvironment;
            $this->_query['ExportToS3.S3Bucket'] = $s3Bucket;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeExportTasks() {
            $this->_query['Action'] = 'DescribeExportTasks';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setDescription($description) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Description'] = $description;
            return $this;
        }

        public function setDiskImageFormat($diskImageFormat) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ExportToS3.DiskImageFormat'] = $diskImageFormat;
            return $this;
        }

        public function setContainerFormat($containerFormat) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ExportToS3.ContainerFormat'] = $containerFormat;
            return $this;
        }

        public function setS3Prefix($s3Prefix) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ExportToS3.S3Prefix'] = $s3Prefix;
            return $this;
        }

        public function setExportTaskId($exportTaskId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ExportTaskId_'] [isset($this->_query['ExportTaskId_']) ? count($this->_query['ExportTaskId_']) + 1 : 1] = $exportTaskId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_VmImport */
if (!class_exists('Eden_Amazon_Ec2_VmImport')) {

    class Eden_Amazon_Ec2_VmImport extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function cancelConversionTask($conversionTaskId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CancelConversionTask';
            $this->_query['ConversionTaskId'] = $conversionTaskId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeConversionTasks() {
            $this->_query['Action'] = 'DescribeConversionTasks';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function importVolume($conversionTaskId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string', 'int');
            $this->_query['Action'] = 'ImportVolume';
            $this->_query['AvailabilityZone'] = $availabilityZone;
            $this->_query['Image.Format'] = $format;
            $this->_query['Image.Bytes'] = $bytes;
            $this->_query['Image.ImportManifestUrl'] = $importManifestUrl;
            $this->_query['Volume.Size'] = $size;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setDescription($description) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Description'] = $description;
            return $this;
        }

        public function setConversionTaskId($conversionTaskId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['ConversionTaskId_'] [isset($this->_query['ConversionTaskId_']) ? count($this->_query['ConversionTaskId_']) + 1 : 1] = $conversionTaskId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_VpnConnections */
if (!class_exists('Eden_Amazon_Ec2_VpnConnections')) {

    class Eden_Amazon_Ec2_VpnConnections extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createVpnConnection($type, $customerGatewayId, $vpnGatewayId) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query['Action'] = 'CreateVpnConnection';
            $this->_query['Type'] = $type;
            $this->_query['CustomerGatewayId'] = $customerGatewayId;
            $this->_query['VpnGatewayId'] = $vpnGatewayId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteVpnConnection($vpnConnectionId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteVpnConnection';
            $this->_query['VpnConnectionId'] = $vpnConnectionId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeVpnConnections() {
            $this->_query['Action'] = 'DescribeVpnConnections';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setStaticRoutesOnly($options) {
            Eden_Amazon_Error::i()->argument(1, 'bool');
            $this->_query['Options.StaticRoutesOnly'] = $options;
            return $this;
        }

        public function setVpnConnectionId($vpnConnectionId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['VpnConnectionId_'] [isset($this->_query['VpnConnectionId_']) ? count($this->_query['VpnConnectionId_']) + 1 : 1] = $vpnConnectionId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_Vpc */
if (!class_exists('Eden_Amazon_Ec2_Vpc')) {

    class Eden_Amazon_Ec2_Vpc extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createVpc($cidrBlock, $instanceTenancy = NULL) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            $this->_query['Action'] = 'CreateVpc';
            $this->_query['CidrBlock'] = $cidrBlock;
            $this->_query['instanceTenancy'] = $instanceTenancy;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function deleteVpc($vpcId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteVpc';
            $this->_query['VpcId'] = $vpcId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeVpcs() {
            $this->_query['Action'] = 'DescribeVpcs';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setVpcId($vpcId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['VpcId_'] [isset($this->_query['VpcId_']) ? count($this->_query['VpcId_']) + 1 : 1] = $vpcId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ec2_Windows */
if (!class_exists('Eden_Amazon_Ec2_Windows')) {

    class Eden_Amazon_Ec2_Windows extends Eden_Amazon_Ec2_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function bundleInstance($instancesId, $bucket, $prefix, $uploadPolicy, $signature) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string');
            $this->_query['Action'] = 'BundleInstance';
            $this->_query['InstanceId'] = $instancesId;
            $this->_query['Storage.S3.Bucket'] = $bucket;
            $this->_query['Storage.S3.Prefix'] = $prefix;
            $this->_query['Storage.S3.UploadPolicy'] = $uploadPolicy;
            $this->_query['Storage.S3.UploadPolicySignature'] = $signature;
            $this->_query['Storage.S3.AWSAccessKeyId'] = $this->_accessKey;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function cancelBundleTask($bundleId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CancelBundleTask';
            $this->_query['BundleId'] = $bundleId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function describeBundleTasks() {
            $this->_query['Action'] = 'DescribeBundleTasks';
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function getPasswordData($instanceId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'GetPasswordData';
            $this->_query['InstanceId'] = $instanceId;
            return $this->_getResponse(self::AMAZON_EC2_HOST, $this->_query);
        }

        public function setBundleId($bundleId) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['BundleId_'] [isset($this->_query['BundleId_']) ? count($this->_query['BundleId_']) + 1 : 1] = $bundleId;
            return $this;
        }

    }

}
/* Eden_Amazon_Ecs */
if (!class_exists('Eden_Amazon_Ecs')) {

    class Eden_Amazon_Ecs extends \Eden {

        protected $_publicKey = NULL;
        protected $_privateKey = NULL;
        protected $_host = 'ecs.amazonaws.';
        protected $_uri = '/onca/xml';
        protected $_params = array();
        protected $_method = 'GET';
        protected $_canonicalizedQuery = NULL;
        protected $_stringToSign = NULL;
        protected $_signature = NULL;
        protected $_requestUrl = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($privateKey, $publicKey) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_privateKey = $privateKey;
            $this->_publicKey = $publicKey;
        }

        public function setAssociateTag($tag) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['AssociateTag'] = $tag;
            return $this;
        }

        public function setCountry($country = 'com') {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_host = $this->_host . $country;
            return $this;
        }

        public function setIdType($type) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['IdType'] = $type;
            return $this;
        }

        public function setItemId($id) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'int');
            $this->_params['ItemId'] = $id;
            return $this;
        }

        public function setKeyword($keyword) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'int');
            $this->_params['Keywords'] = $keyword;
            return $this;
        }

        public function setMethod($method) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_method = $method;
            return $this;
        }

        public function setOperation($operation) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Operation'] = $operation;
            return $this;
        }

        public function setPage($page = 1) {
            Eden_Amazon_Error::i()->argument(1, 'int');
            $this->_params['ItemPage'] = $page;
            return $this;
        }

        public function getResponse() {
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            ksort($this->_params);
            $canonicalizedQuery = array();
            foreach ($this->_params as $param => $value) {
                $param = str_replace("%7E", "~", rawurlencode($param));
                $value = str_replace("%7E", "~", rawurlencode($value));
                $canonicalizedQuery[] = $param . "=" . $value;
            }$this->_canonicalizedQuery = implode("&", $canonicalizedQuery);
            $this->_stringToSign = $this->_method . "\n" . $this->_host . "\n" . $this->_uri . "\n" . $this->_canonicalizedQuery;
            $this->_setSignature();
            $this->_requestUrl = 'http://' . $this->_host . $this->_uri . '?' . $this->_canonicalizedQuery . '&Signature=' . $this->_signature;
            return $this->_sendRequest();
        }

        public function setResponseGroup($group) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['ResponseGroup'] = $group;
            return $this;
        }

        public function setSearchIndex($index = 'All') {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['SearchIndex'] = $index;
            return $this;
        }

        public function setService($service) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Service'] = $service;
            return $this;
        }

        public function setTimestamp($time = NULL) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'int', 'null');
            if ($time == NULL) {
                $time = time();
            }if (is_string($time)) {
                $time = strtotime($time);
            }$this->_params['Timestamp'] = gmdate("Y-m-d\TH:i:s\Z", $time);
            return $this;
        }

        public function setVersion($version) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Version'] = $version;
            return $this;
        }

        protected function _sendRequest() {
            return Eden_Curl::i()->setUrl($this->_requestUrl)->verifyHost(false)->verifyPeer(false)->setTimeout(60)->getResponse();
        }

        protected function _setSignature() {
            $this->_signature = base64_encode(hash_hmac("sha256", $this->_stringToSign, $this->_privateKey, True));
            $this->_signature = str_replace("%7E", "~", rawurlencode($this->_signature));
            return $this;
        }

    }

}
/* Eden_Amazon_S3 */
if (!class_exists('Eden_Amazon_S3')) {

    class Eden_Amazon_S3 extends \Eden {

        const ACL_PRIVATE = 'private';
        const ACL_PUBLIC_READ = 'public-read';
        const ACL_PUBLIC_READ_WRITE = 'public-read-write';
        const ACL_AUTHENTICATED_READ = 'authenticated-read';
        const GET = 'GET';
        const PUT = 'PUT';
        const DELETE = 'DELETE';
        const HEAD = 'HEAD';

        protected $_meta = array();
        protected $_host = 's3.amazonaws.com';
        protected $_accessKey = NULL;
        protected $_accessSecret = NULL;
        protected $_response = NULL;
        protected $_ssl = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($key, $secret, $host = 's3.amazonaws.com', $ssl = true) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'bool');
            $this->_host = $host;
            $this->_accessKey = $key;
            $this->_accessSecret = $secret;
            $this->_ssl = $ssl;
        }

        public function addBucket($bucket, $location = false) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'bool');
            $data = NULL;
            $headers = array();
            $amazon = array('x-amz-acl' => self::ACL_PRIVAT);
            if ($location !== false) {
                $dom = new DOMDocument;
                $config = $dom->createElement('CreateBucketConfiguration');
                $constraint = $dom->createElement('LocationConstraint', strtoupper($location));
                $config->appendChild($constraint);
                $dom->appendChild($config);
                $data = $dom->saveXML();
                $headers['Content-Type'] = 'application/xml';
            }return $this->_setResponse(self::PUT, $bucket, '/', array(), $data, $headers, $amazon);
        }

        public function addFile($bucket, $path, $data, $permission = self::ACL_PRIVATE, $metaData = array()) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'array');
            $headers = $amazon = array();
            $amazon['x-amz-acl'] = $permission;
            foreach ($metaData as $key => $value) {
                $headers[$key] = $value;
            }if (strpos($path, '/') !== 0) {
                $path = '/' . $path;
            }return $this->_setResponse(self::PUT, $bucket, $path, array(), $data, $headers, $amazon);
        }

        public function deleteBucket($bucket) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            return $this->_setResponse(self::DELETE, $bucket);
        }

        public function deleteFile($bucket, $path) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_setResponse(self::DELETE, $bucket, $path);
        }

        public function deleteFolder($bucket, $path) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $list = $this->getBucket($bucket);
            if (strpos($path, '/') === 0) {
                $path = substr($path, 1);
            }if (substr($path, -1) == '/') {
                $path = substr($path, 0, -1);
            }$files = array();
            foreach ($list as $object) {
                if (strpos($object['name'], $path) !== 0) {
                    continue;
                }$this->deleteFile($bucket, '/' . $object['name']);
            }return $this->_response;
        }

        public function getBucket($name, $prefix = NULL, $marker = NULL, $maxKeys = NULL, $delimiter = NULL) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string', 'null')->argument(3, 'string', 'null')->argument(4, 'string', 'null')->argument(5, 'string', 'null');
            $bucket = array();
            do {
                $query = array();
                if ($prefix) {
                    $query['prefix'] = $prefix;
                }if ($marker) {
                    $query['marker'] = $marker;
                }if ($maxKeys) {
                    $query['max-keys'] = $maxKeys;
                }if ($delimiter) {
                    $query['delimiter'] = $delimiter;
                }$this->_setResponse('GET', $name, '/', $query);
                if ($this->_meta['info'] != 200) {
                    return $this->_response;
                }$nextMarker = NULL;
                foreach ($this->_response->Contents as $content) {
                    $bucket[(string) $content->Key] = array('name' => (string) $content->Key, 'time' => strtotime((string) $content->LastModified), 'size' => (string) $content->Size, 'hash' => substr((string) $content->ETag, 1, -1));
                    $nextMarker = (string) $content->Key;
                }foreach ($this->_response->CommonPrefixes as $prefix) {
                    $bucket['prefixes'][] = (string) $prefixes->Prefix;
                }if (isset($this->_response->IsTruncated) && $this->_response->IsTruncated == 'false') {
                    break;
                }if (isset($this->_response->NextMarker)) {
                    $nextMarker = (string) $this->_response->NextMarker;
                }
            } while (!$maxKeys && $nextMarker);
            return $bucket;
        }

        public function getBuckets() {
            return $this->_setResponse(self::GET);
        }

        public function getFile($bucket, $path) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_setResponse(self::GET, $bucket, $path);
        }

        public function getFileInfo($bucket, $path) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            if (strpos($path, '/') !== 0) {
                $path = '/' . $path;
            }return $this->_setResponse(self::HEAD, $bucket, $path);
        }

        public function getFiles($bucket, $path = NULL, $prefix = NULL, $marker = NULL, $maxKeys = NULL, $delimiter = NULL) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string', 'null')->argument(3, 'string', 'null')->argument(4, 'string', 'null')->argument(5, 'string', 'null')->argument(6, 'string', 'null');
            $bucket = $this->getBucket($bucket, $prefix, $marker, $maxKeys, $delimiter);
            if (strpos($path, '/') === 0) {
                $path = substr($path, 1);
            }if (substr($path, -1) == '/') {
                $path = substr($path, 0, -1);
            }$files = array();
            foreach ($bucket as $object) {
                $name = $object['name'];
                if ($path) {
                    if (strpos($name, $path . '/') !== 0) {
                        continue;
                    }$name = substr($name, strlen($path . '/'));
                }if (strpos($name, '/') !== false || strpos($name, '_$folder$') !== false) {
                    continue;
                }$files[$name] = true;
            }return array_keys($files);
        }

        public function getFolders($bucket, $path = NULL, $prefix = NULL, $marker = NULL, $maxKeys = NULL, $delimiter = NULL) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string', 'null')->argument(3, 'string', 'null')->argument(4, 'string', 'null')->argument(5, 'string', 'null')->argument(6, 'string', 'null');
            $bucket = $this->getBucket($bucket, $prefix, $marker, $maxKeys, $delimiter);
            if (strpos($path, '/') === 0) {
                $path = substr($path, 1);
            }if (substr($path, -1) == '/') {
                $path = substr($path, 0, -1);
            }$folders = array();
            foreach ($bucket as $object) {
                $name = $object['name'];
                if ($path) {
                    if (strpos($name, $path . '/') !== 0) {
                        continue;
                    }$name = substr($name, strlen($path . '/'));
                }$paths = explode('/', $name);
                if (strpos($paths[0], '_$folder$') !== false) {
                    $paths[0] = str_replace('_$folder$', '', $paths[0]);
                }$folders[$paths[0]] = true;
            }return array_keys($folders);
        }

        public function getFolderSize($bucket, $path) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $bucket = $this->getBucket($bucket);
            if (strpos($path, '/') === 0) {
                $path = substr($path, 1);
            }if (substr($path, -1) == '/') {
                $path = substr($path, 0, -1);
            }$size = 0;
            foreach ($bucket as $object) {
                if (strpos($object['name'], $path . '/') !== 0) {
                    continue;
                }$size +=$object['size'];
            }return $size;
        }

        public function getMeta($key = NULL) {
            if (isset($this->_meta[$key])) {
                return $this->_meta[$key];
            }return $this->_meta;
        }

        public function getPermissions($bucket, $path = '/') {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query['acl'] = NULL;
            $response = $this->_setResponse('GET', $bucket, $path);
            if ($this->_meta['info'] != 200) {
                return $response;
            }$permission = array();
            if (isset($this->_response->Owner, $this->_response->Owner->ID, $this->_response->Owner->DisplayName)) {
                $permission['owner'] = array('id' => $this->_response->Owner->ID, 'name' => $this->_response->Owner->DisplayName);
            }if (isset($this->_response->AccessControlList)) {
                $acp['users'] = array();
                foreach ($this->_response->AccessControlList->Grant as $grant) {
                    foreach ($grant->Grantee as $grantee) {
                        if (isset($grantee->ID, $grantee->DisplayName)) {
                            $permission['users'][] = array('type' => 'CanonicalUser', 'id' => $grantee->ID, 'name' => $grantee->DisplayName, 'permission' => $grant->Permission);
                        } else if (isset($grantee->EmailAddress)) {
                            $permission['users'][] = array('type' => 'AmazonCustomerByEmail', 'email' => $grantee->EmailAddress, 'permission' => $grant->Permission);
                        } else if (isset($grantee->URI)) {
                            $permission['users'][] = array('type' => 'Group', 'uri' => $grantee->URI, 'permission' => $grant->Permission);
                        }
                    }
                }
            }return $permission;
        }

        public function setPermissions($bucket, $path = '/', array $acp = array()) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $dom = new DOMDocument;
            $dom->formatOutput = true;
            $policy = $dom->createElement('AccessControlPolicy');
            $list = $dom->createElement('AccessControlList');
            $owner = $dom->createElement('Owner');
            $owner->appendChild($dom->createElement('ID', $acp['owner']['id']));
            $owner->appendChild($dom->createElement('DisplayName', $acp['owner']['name']));
            $policy->appendChild($owner);
            foreach ($acp['acl'] as $permission) {
                $grant = $dom->createElement('Grant');
                $grantee = $dom->createElement('Grantee');
                $grantee->setAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
                if (isset($permission['id'])) {
                    $grantee->setAttribute('xsi:type', 'CanonicalUser');
                    $grantee->appendChild($dom->createElement('ID', $permission['id']));
                } elseif (isset($permission['email'])) {
                    $grantee->setAttribute('xsi:type', 'AmazonCustomerByEmail');
                    $grantee->appendChild($dom->createElement('EmailAddress', $permission['email']));
                } elseif ($permission['type'] == 'Group') {
                    $grantee->setAttribute('xsi:type', 'Group');
                    $grantee->appendChild($dom->createElement('URI', $permission['uri']));
                }$grant->appendChild($grantee);
                $grant->appendChild($dom->createElement('Permission', $permission['permission']));
                $list->appendChild($grant);
            }$policy->appendChild($list);
            $dom->appendChild($policy);
            $data = $dom->saveXML();
            $query = array('acl' => NULL);
            $header = array('Content-Type' => 'application/xml');
            return $this->_setResponse('PUT', $bucket, $path, $query, $data, $headers);
        }

        protected function _getHost($bucket = NULL) {
            if (!$bucket) {
                return $this->_host;
            }return strtolower($bucket) . '.' . $this->_host;
        }

        protected function _getPath($bucket = NULL, $path = '/', array $query = array()) {
            if ($bucket) {
                return '/' . strtolower($bucket) . $path;
            }$keys = array_keys($query);
            foreach ($keys as $key) {
                if (in_array($key, array('acl', 'location', 'torrent', 'logging'))) {
                    $query = http_build_query($query);
                    $link = '?';
                    if (strpos($path, '?') !== false) {
                        $link = '&';
                    }return $path . $link . $query;
                }
            }return $path;
        }

        protected function _getSignature($string) {
            if (extension_loaded('hash')) {
                $hash = base64_encode(hash_hmac('sha1', $string, $this->_accessSecret, true));
            } else {
                $pad1 = str_pad($this->_accessSecret, 64, chr(0x00)) ^ str_repeat(chr(0x36), 64);
                $pad2 = str_pad($this->_accessSecret, 64, chr(0x00)) ^ str_repeat(chr(0x5c), 64);
                $pack1 = pack('H*', sha1($pad1 . $string));
                $pack2 = pack('H*', sha1($pad2 . $pack1));
                $hash = base64_encode($pack2);
            }return 'AWS ' . $this->_accessKey . ':' . $hash;
        }

        protected function _getUrl($host, $path, $query = NULL) {
            if (is_array($query)) {
                $query = http_build_query($query);
            }$link = '?';
            if (strpos($path, '?') !== false) {
                $link = '&';
            }$protocol = 'http://';
            if ($this->_ssl && extension_loaded('openssl')) {
                $protocol = 'https://';
            }return $protocol . $host . $path . $link . $query;
        }

        protected function _responseHeaderCallback(&$curl, &$data) {
            $strlen = strlen($data);
            if ($strlen <= 2) {
                return $strlen;
            }if (substr($data, 0, 4) == 'HTTP') {
                $this->_meta['code'] = substr($data, 9, 3);
                return $strlen;
            }list($header, $value) = explode(': ', trim($data), 2);
            if ($header == 'Last-Modified') {
                $this->_meta['headers']['time'] = strtotime($value);
            } else if ($header == 'Content-Length') {
                $this->_meta['headers']['size'] = $value;
            } else if ($header == 'Content-Type') {
                $this->_meta['headers']['type'] = $value;
            } else if ($header == 'ETag') {
                $this->_meta['headers']['hash'] = $value{0} == '"' ? substr($value, 1, -1) : $value;
            } else if (preg_match('/^x-amz-meta-.*$/', $header)) {
                $this->_meta['headers'][$header] = $value;
            }return $strlen;
        }

        protected function _responseWriteCallback(&$curl, &$data) {
            $this->_response.=$data;
            return strlen($data);
        }

        protected function _setResponse($action, $bucket = NULL, $path = '/', array $query = array(), $data = NULL, array $headers = array(), array $amazon = array()) {
            $host = $this->_getHost($bucket);
            $url = $this->_getUrl($host, $path, $query);
            $path = $this->_getPath($bucket, $path);
            ksort($amazon);
            $curlHeaders = $amazonHeaders = array();
            $headers['Host'] = $host;
            $headers['Date'] = gmdate('D,d M Y H:i:s T');
            foreach ($amazon as $header => $value) {
                $curlHeaders[] = $header . ': ' . $value;
                $amazonHeaders[] = strtolower($header) . ':' . $value;
            }foreach ($headers as $header => $value) {
                $curlHeaders[] = $header . ': ' . $value;
            }$amazonHeaders = "\n" . implode("\n", $amazonHeaders);
            if (!trim($amazonHeaders)) {
                $amazonHeaders = NULL;
            }if (!isset($headers['Content-MD5'])) {
                $headers['Content-MD5'] = NULL;
            }if (!isset($headers['Content-Type'])) {
                $headers['Content-Type'] = NULL;
            }$signature = array($action, $headers['Content-MD5'], $headers['Content-Type'], $headers['Date'] . $amazonHeaders, $path);
            $signature = implode("\n", $signature);
            if ($headers['Host'] == 'cloudfront.amazonaws.com') {
                $signature = $headers['Date'];
            }$curlHeaders[] = 'Authorization: ' . $this->_getSignature($signature);
            $curl = Eden_Curl::i()->setUserAgent('S3/php')->setUrl($url)->setHeaders($curlHeaders)->setHeader(false)->setWriteFunction(array(&$this, '_responseWriteCallback'))->verifyHost(true)->verifyPeer(true);
            switch ($action) {
                case 'GET': break;
                case 'PUT': case 'POST': $fh = fopen('php://memory', 'rw');
                    fwrite($fh, $data);
                    rewind($fh);
                    $curl->setPut(true)->setInFile($fh)->setInFileSize(strlen($data));
                    break;
                case 'HEAD': $curl->setCustomRequest('HEAD')->setNobody(true);
                    break;
                case 'DELETE': $curl->setCustomRequest('DELETE');
                    break;
            }$response = $curl->getResponse();
            if (!empty($response)) {
                if ($this->_isXml($response)) {
                    $this->_response = simplexml_load_string($response);
                }
            } else {
                $this->_response = $curl->getMeta();
            }$this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['headers'] = $curlHeaders;
            $this->_meta['query'] = $data;
            $this->_meta['path'] = $path;
            $this->_meta['bucket'] = $bucket;
            $this->_meta['response'] = $this->_response;
            return $this->_response;
        }

        protected function _isXml($xml) {
            if (is_array($xml) || is_null($xml)) {
                return false;
            }libxml_use_internal_errors(true);
            $doc = new DOMDocument('1.0', 'utf-8');
            $doc->loadXML($xml);
            $errors = libxml_get_errors();
            if (empty($errors)) {
                return true;
            } else {
                return false;
            }
        }

    }

}
/* Eden_Amazon_Ses */
if (!class_exists('Eden_Amazon_Ses')) {

    class Eden_Amazon_Ses extends Eden_Amazon_Base {

        protected $_host = 'email.us-east-1.amazonaws.com';
        protected $_data = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function setIdentity($identity) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Identity'] = $identity;
            return $this;
        }

        public function addIdentity($identity) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Identities.member'][isset($this->_params['Identities.member']) ? count($this->_params['Identities.member']) + 1 : 1] = $identity;
            return $this;
        }

        public function setEmailAddress($email) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['EmailAddress'] = $email;
            return $this;
        }

        public function setIdentityType($type) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['IdentityType'] = $type;
            return $this;
        }

        public function setMaxResult($max) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['MaxItems'] = $max;
            return $this;
        }

        public function setMaxRate($max) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['MaxItems'] = $max;
            return $this;
        }

        public function setNextToken($token) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['NextToken'] = $token;
            return $this;
        }

        public function addTo($to) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Destination.ToAddresses.member'][isset($this->_params['Destination.ToAddresses.member']) ? count($this->_params['Destination.ToAddresses.member']) + 1 : 1] = $to;
            return $this;
        }

        public function addCc($cc) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Destination.CcAddresses.member'][isset($this->_params['Destination.CcAddresses.member']) ? count($this->_params['Destination.CcAddresses.member']) + 1 : 1] = $cc;
            return $this;
        }

        public function addBcc($bcc) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Destination.BccAddresses.member'][isset($this->_params['Destination.BccAddresses.member']) ? count($this->_params['Destination.BccAddresses.member']) + 1 : 1] = $bcc;
            return $this;
        }

        public function setSubject($subject, $charset = false) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'bool');
            $data = ($charset) ? 'Data.Charset' : 'Data';
            $this->_params['Message.Subject.' . $data] = $subject;
            return $this;
        }

        public function setBody($body, $html = false, $charset = false) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'bool')->argument(3, 'bool');
            $type = ($html) ? 'Html' : 'Text';
            $data = ($charset) ? 'Charset' : 'Data';
            $this->_params['Message.Body.' . $type . '.' . $data] = $body;
            return $this;
        }

        public function addReplyTo($replyTo) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['ReplyToAddresses.member'][isset($this->_params['ReplyToAddresses.member']) ? count($this->_params['ReplyToAddresses.member']) + 1 : 1] = $replyTo;
            return $this;
        }

        public function setReturnPath($path) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['ReturnPath'] = $path;
            return $this;
        }

        public function setSource($email) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Source'] = $email;
            return $this;
        }

        public function addDestination($destination) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Destinations.member'][isset($this->_params['Destinations.member']) ? count($this->_params['Destinations.member']) + 1 : 1] = $destination;
            return $this;
        }

        public function setRawMsg($msg) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['RawMessage.Data'] = $msg;
            return $this;
        }

        public function setDkim($dkim) {
            Eden_Amazon_Error::i()->argument(1, 'bool');
            $this->_params['DkimEnabled'] = $dkim;
            return $this;
        }

        public function setForwarding($forward) {
            Eden_Amazon_Error::i()->argument(1, 'bool');
            $this->_params['ForwardingEnabled'] = $forward;
            return $this;
        }

        public function setNotificationType($type) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['NotificationType'] = $type;
            return $this;
        }

        public function setTopic($sns) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['SnsTopic'] = $sns;
            return $this;
        }

        public function setDomain($domain) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_params['Domain'] = $domain;
            return $this;
        }

        public function deleteIdentity() {
            $this->_params['Action'] = 'DeleteIdentity';
            return $this->_getResponse();
        }

        public function deleteVerifiedEmail() {
            $this->_params['Action'] = 'DeleteVerifiedEmailAddress';
            return $this->_getResponse();
        }

        public function getIdentityDetail() {
            $this->_params['Action'] = 'GetIdentityDkimAttributes';
            return $this->_getResponse();
        }

        public function getNotifications() {
            $this->_params['Action'] = 'GetIdentityNotificationAttributes';
            return $this->_getResponse();
        }

        public function getVerificationAttributes() {
            $this->_params['Action'] = 'GetIdentityVerificationAttributes';
            return $this->_getResponse();
        }

        public function getQuota() {
            $this->_params['Action'] = 'GetSendQuota';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function getStatistics() {
            $this->_params['Action'] = 'GetSendStatistics';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function getIdentities() {
            $this->_params['Action'] = 'ListIdentities';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function getVerifiedEmails() {
            $this->_params['Action'] = 'ListVerifiedEmailAddresses';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function send() {
            $this->_params['Action'] = 'SendEmail';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function sendRawMail() {
            $this->_params['Action'] = 'SendRawEmail';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function setDkimIdentity() {
            $this->_params['Action'] = 'SetIdentityDkimEnabled';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function setIdentityForwarding() {
            $this->_params['Action'] = 'SetIdentityFeedbackForwardingEnabled';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function setNotificationTopic() {
            $this->_params['Action'] = 'SetIdentityNotificationTopic';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function verifyDomainDkim() {
            $this->_params['Action'] = 'VerifyDomainDkim';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function verifyDomainIdentity() {
            $this->_params['Action'] = 'VerifyDomainIdentity';
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            return $this->_getResponse();
        }

        public function verifyEmail() {
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            $this->_params['Action'] = 'VerifyEmailAddress';
            return $this->_getResponse();
        }

        public function verifyEmailIdentity() {
            $this->_params['AWSAccessKeyId'] = $this->_publicKey;
            $this->_params['Action'] = 'VerifyEmailIdentity';
            return $this->_getResponse();
        }

        protected function _setSignature() {
            $this->_signature = base64_encode(hash_hmac('sha256', $this->_date, $this->_privateKey, true));
            return $this;
        }

        protected function _getResponse() {
            foreach ($this->_params as $param => $value) {
                if (is_array($value)) {
                    foreach ($value as $k => $v) {
                        $canonicalizedQuery[] = str_replace("%7E", "~", rawurlencode($param . '.' . $k)) . '=' . str_replace("%7E", "~", rawurlencode($v));
                    }
                } else {
                    $canonicalizedQuery[] = str_replace("%7E", "~", rawurlencode($param)) . '=' . str_replace("%7E", "~", rawurlencode($value));
                }
            }sort($canonicalizedQuery, SORT_STRING);
            $this->_date = gmdate('D,d M Y H:i:s e');
            $this->_canonicalizedQuery = implode("&", $canonicalizedQuery);
            $this->_setSignature();
            $query = $this->_canonicalizedQuery;
            $auth = 'AWS3-HTTPS AWSAccessKeyId=' . $this->_publicKey;
            $auth.=',Algorithm=HmacSHA256,Signature=' . $this->_signature;
            $headers = array('X-Amzn-Authorization: ' . $auth, 'Date: ' . $this->_date, 'Host: ' . $this->_host);
            return $this->_postRequest($query, $headers);
        }

    }

}
/* Eden_Amazon_Sns */
if (!class_exists('Eden_Amazon_Sns')) {

    class Eden_Amazon_Sns extends \Eden {

        const AMAZON_SNS_URL = 'http://sns.us-east-1.amazonaws.com/';
        const AMAZON_SNS_HOST = 'sns.us-east-1.amazonaws.com';
        const VERSION = 'Version';
        const SIGNATURE = 'Signature';
        const SIGNATURE_VERSION = 'SignatureVersion';
        const SIGNATURE_METHOD = 'SignatureMethod';
        const ACCESS_KEY = 'AWSAccessKeyId';
        const TIMESTAMP = 'Timestamp';

        protected $_query = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($accessKey, $accessSecret) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_accessKey = $accessKey;
            $this->_accessSecret = $accessSecret;
        }

        public function addPermission($topic, $label, $permissions) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'array');
            $this->_query['Action'] = 'AddPermission';
            $this->_query['TopicArn'] = $topic;
            $this->_query['Label'] = $label;
            $memberFlatArray = array();
            $permissionFlatArray = array();
            foreach ($permissions as $member => $permission) {
                $memberFlatArray[] = $member;
                $permissionFlatArray[] = $permission;
            }for ($x = 0; $x <= count($memberFlatArray); $x++) {
                if (isset($memberFlatArray[$x], $permissionFlatArray[$x])) {
                    $y = $x + 1;
                    $this->_query['ActionName.member.' . $y] = $memberFlatArray[$x];
                    $this->_query['AWSAccountID.member.' . $y] = $permissionFlatArray[$x];
                }
            }return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function confirmSubscription($token, $topicArn) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'ConfirmSubscription';
            $this->_query['Token'] = $token;
            $this->_query['TopicArn'] = $topicArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function createTopic($name) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'CreateTopic';
            $this->_query['Name'] = $name;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function deleteTopic($topicArn) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'DeleteTopic';
            $this->_query['TopicArn'] = $topicArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function getSubscriptionAttributes($subscriptionArn) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'GetSubscriptionAttributes';
            $this->_query['SubscriptionArn'] = $subscriptionArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function getTopicAttributes($topicArn) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'GetTopicAttributes';
            $this->_query['TopicArn'] = $topicArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function listSubscriptions() {
            $this->_query['Action'] = 'ListSubscriptions';
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function listSubscriptionsByTopic($topicArn) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'ListSubscriptionsByTopic';
            $this->_query['TopicArn'] = $topicArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function listTopics() {
            $this->_query['Action'] = 'ListTopics';
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function publish($message, $topicArn, $subject = NULL) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string', 'null');
            $this->_query['Action'] = 'Publish';
            $this->_query['Message'] = $message;
            $this->_query['TopicArn'] = $topicArn;
            $this->_query['Subject'] = $subject;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function removePermission($label, $topicArn) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['Action'] = 'RemovePermission';
            $this->_query['Label'] = $label;
            $this->_query['TopicArn'] = $topicArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function setSubscriptionAttributes($attributeName, $attributeValue, $subscriptionArn) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query['Action'] = 'SetSubscriptionAttributes';
            $this->_query['AttributeName'] = $attributeName;
            $this->_query['AttributeValue'] = $attributeValue;
            $this->_query['SubscriptionArn'] = $subscriptionArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function setTopicAttributes($attributeName, $attributeValue, $topicArn) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query['Action'] = 'SetTopicAttributes';
            $this->_query['AttributeName'] = $attributeName;
            $this->_query['AttributeValue'] = $attributeValue;
            $this->_query['TopicArn'] = $topicArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function subscribe($endpoint, $protocol, $topicArn) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query['Action'] = 'Subscribe';
            $this->_query['Endpoint'] = $endpoint;
            $this->_query['Protocol'] = $protocol;
            $this->_query['TopicArn'] = $topicArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function unsubscribe($subscriptionArn) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['Action'] = 'Unsubscribe';
            $this->_query['SubscriptionArn'] = $subscriptionArn;
            return $this->_getResponse(self::AMAZON_SNS_HOST, $this->_query);
        }

        public function setNextToken($nextToken) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['NextToken'] = $nextToken;
            return $this;
        }

        public function setAuthenticateOnUnsubscribe($authenticateOnUnsubscribe) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['AuthenticateOnUnsubscribe'] = $authenticateOnUnsubscribe;
            return $this;
        }

        public function setMessageStructure($messageStructure) {
            Eden_Amazon_Error::i()->argument(1, 'string');
            $this->_query['MessageStructure'] = $messageStructure;
            return $this;
        }

        public function getMeta() {
            return $this->_meta;
        }

        protected function _isXml($xml) {
            Eden_Amazon_Error::i()->argument(1, 'string', 'array', 'object', 'null');
            if (is_array($xml) || is_null($xml)) {
                return false;
            }libxml_use_internal_errors(true);
            $doc = new DOMDocument('1.0', 'utf-8');
            $doc->loadXML($xml);
            $errors = libxml_get_errors();
            return empty($errors);
        }

        protected function _generateSignature($host, $query) {
            $signature = "GET\n";
            $signature.="$host\n";
            $signature.="/\n";
            ksort($query);
            $first = true;
            foreach ($query as $key => $value) {
                $signature.=(!$first ? '&' : '') . rawurlencode($key) . '=' . rawurlencode($value);
                $first = false;
            }$signature = hash_hmac('sha256', $signature, $this->_accessSecret, true);
            $signature = base64_encode($signature);
            return $signature;
        }

        protected function _accessKey($array) {
            foreach ($array as $key => $val) {
                if (is_array($val)) {
                    $array[$key] = $this->_accessKey($val);
                }if ($val == NULL || empty($val)) {
                    unset($array[$key]);
                }
            }return $array;
        }

        protected function _formatQuery($rawQuery) {
            foreach ($rawQuery as $key => $value) {
                if (is_array($value)) {
                    foreach ($value as $k => $v) {
                        $keyValue = explode('_', $key);
                        if (!empty($keyValue[1])) {
                            $name = $keyValue[0] . '.' . $k . '.' . $keyValue[1];
                        } else {
                            $name = $keyValue[0] . '.' . $k;
                        }$query[str_replace("%7E", "~", $name)] = str_replace("%7E", "~", $v);
                    }
                } else {
                    $query[str_replace("%7E", "~", $key)] = str_replace("%7E", "~", $value);
                }
            }return $query;
        }

        protected function _getResponse($host, $rawQuery) {
            $rawQuery = $this->_accessKey($rawQuery);
            ksort($rawQuery);
            $query = $this->_formatQuery($rawQuery);
            $domain = "https://$host/";
            $query[self::ACCESS_KEY] = $this->_accessKey;
            $query[self::TIMESTAMP] = gmdate('Y-m-d\TH:i:s\Z');
            ;
            $query[self::SIGNATURE_METHOD] = 'HmacSHA256';
            $query[self::SIGNATURE_VERSION] = 2;
            $query[self::SIGNATURE] = $this->_generateSignature($host, $query);
            $url = $domain . '?' . http_build_query($query);
            $curl = Eden_Curl::i()->setUrl($url)->verifyHost(false)->verifyPeer(false)->setTimeout(60);
            $response = $curl->getResponse();
            if ($this->_isXml($response)) {
                $response = simplexml_load_string($response);
            }$this->_meta['url'] = $url;
            $this->_meta['query'] = $query;
            $this->_meta['curl'] = $curl->getMeta();
            $this->_meta['response'] = $response;
            return $response;
        }

    }

}
/* Eden_Amazon */
if (!class_exists('Eden_Amazon')) {

    class Eden_Amazon extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function ec2($accessKey, $accessSecret) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            return Eden_Amazon_Ec2::i($accessKey, $accessSecret);
        }

        public function ecs($privateKey, $publicKey) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            return Eden_Amazon_Ecs::i($privateKey, $publicKey);
        }

        public function s3($accessKey, $accessSecret) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            return Eden_Amazon_S3::i($accessKey, $accessSecret);
        }

        public function ses($privateKey, $publicKey) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            return Eden_Amazon_Ses::i($privateKey, $publicKey);
        }

        public function sns($accessKey, $accessSecret) {
            Eden_Amazon_Error::i()->argument(1, 'string')->argument(2, 'string');
            return Eden_Amazon_Sns::i($accessKey, $accessSecret);
        }

    }

}
/* Eden_Google */
if (!class_exists('Eden_Google')) {

    class Eden_Google extends \Eden {
        public function hello(){
            echo "eee";
        }
        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function auth($clientId, $clientSecret, $redirect, $apiKey = NULL) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'url')->argument(4, 'string', 'null');
            return Eden_Google_Oauth::i($clientId, $clientSecret, $redirect, $apiKey);
        }

        public function analytics($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            return Eden_Google_Analytics::i($token);
        }

        public function calendar($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            return Eden_Google_Calendar::i($token);
        }

        public function checkout($merchantId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return Eden_Google_Checkout_Form::i($merchantId);
        }

        public function contacts($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            return Eden_Google_Contacts::i($token);
        }

        public function drive($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            return Eden_Google_Drive::i($token);
        }

        public function maps($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            return Eden_Google_Maps::i($token);
        }

        public function plus($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            return Eden_Google_Plus::i($token);
        }

        public function shortener($key, $token) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return Eden_Google_Shortener::i($key, $token);
        }

        public function youtube($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return Eden_Google_Youtube::i($token, $developerId);
        }

    }

}
/* Eden_Google_Error */
if (!class_exists('Eden_Google_Error')) {

    class Eden_Google_Error extends Eden_Error {

        const INVALID_ROLE = 'Argument 2 was expecting owner,reader,writer.%s was given';
        const INVALID_TYPE = 'Argument 3 was expecting user,group,domain,anyone.%s was given';
        const INVALID_COLLECTION = 'Argument 2 was expecting plusoners,resharers.%s was given';
        const INVALID_FEEDS_TWO = 'Argument 2 was expecting most_viewed,most_subscribed.%s was given';
        const INVALID_FEEDS_ONE = 'Argument 1 was expecting most_viewed,most_subscribed.%s was given';
        const INVALID_STATUS = 'Argument 2 was expecting accepted,rejected.%s was given';

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Google_Base */
if (!class_exists('Eden_Google_Base')) {

    class Eden_Google_Base extends \Eden {

        const ACCESS_TOKEN = 'access_token';
        const KEY = 'key';
        const MAX_RESULTS = 'maxResults';
        const FORM_HEADER = 'application/x-www-form-urlencoded';
        const CONTENT_TYPE = 'Content-Type: application/json';
        const KIND = 'kind';
        const ID = 'id';
        const OCR = 'ocr';
        const SELF_LINK = 'selfLink';
        const CHILD_LINK = 'childLink';
        const CONVERT = 'convert';
        const PINNED = 'pinned';
        const TITLE = 'title';
        const IS_ROOT = 'isRoot';
        const ETAG = 'etag';
        const NAME = 'name';
        const ROLE = 'role';
        const TYPE = 'type';
        const RESPONSE = 'alt';
        const JSON_FORMAT = 'json';
        const VERSION = 'v';
        const QUERY = 'q';
        const QUERY_STRING = 'query';
        const NEW_REVISION = 'newRevision';
        const OCR_LANGUAGE = 'ocrLanguage';
        const TEXT_LANGUAGE = 'timedTextLanguage';
        const TEXT_TRACKNAME = 'timedTextTrackName';
        const DESCRIPTION = 'description';
        const LAST_VIEW = 'lastViewedByMeDate';
        const MIME_TYPE = 'mimeType';
        const MODIFIED_DATE = 'modifiedDate';
        const AUTH_KEY = 'authKey';
        const WITH_LINK = 'withLink';
        const PHOTO_LINK = 'photoLink';
        const VALUE = 'value';
        const FILESIZE = 'fileSize';
        const SCOPE = 'scope';
        const CALENDAR_ID = 'calendarId';
        const SUMMARY = 'summary';
        const LOCATION = 'location';
        const TIMEZONE = 'timezone';
        const START = 'start';
        const END = 'end';
        const DESTINATION = 'destination';
        const STATUS = 'status';
        const ATTENDEES = 'attendees';
        const COLOR_ID = 'colorId';
        const CREATOR = 'creator';
        const ORGANIZER = 'organizer';
        const REMINDERS = 'reminders';
        const UID = 'iCalUID';
        const TEXT = 'text';
        const TIMEMIN = 'timeMin';
        const TIMEMAX = 'timeMax';
        const ITEMS = 'items';
        const ACCESS_ROLE = 'accessRole';
        const HIDDEN = 'hidden';
        const SELECTED = 'selected';
        const LAST_MODIFY = 'lastModifyingUserName';
        const PUBLISHED = 'published';
        const SOURCE_LANGUAGE = 'sourceLanguage';
        const TARGET_LANGUAGE = 'targetLanguage';
        const GROUP_EXPANSION = 'groupExpansionMax';
        const CALENDAR_EXPANSION = 'calendarExpansionMax';
        const ORIGINAL_FILENAME = 'originalFilename';
        const OUTSIDE_DOMAIN = 'publishedOutsideDomain';
        const DEFAULT_REMINDERS = 'defaultRemiders';
        const SUMMARY_OVERRIDE = 'summaryOverride';
        const PUBLISHED_LINK = 'publishedLink';
        const PUBLISHED_AUTO = 'publishAuto';
        const DOWNLOAD_URL = 'downloadUrl';
        const EXPORT_LINK = 'exportLinks';
        const MD5_CHECKSUM = 'md5Checksum';
        const KEYWORD = 'keyword';
        const CATEGORY = 'category';
        const POST_URL = 'postUrl';
        const UPLOAD_TOKEN = 'uploadToken';
        const REDIRECT_URL = 'redirectUrl';
        const USER = 'user';
        const CHANNEL = 'channel';
        const START_INDEX = 'start-index';
        const ORDER_BY = 'orderby';
        const LIKE = 'like';
        const DISLIKE = 'dislike';
        const RATINGS = 'ratings';
        const USER_NAME = 'userName';
        const VIDEO_ID = 'videoId';
        const POSITION = 'position';
        const COMMENT = 'comment';
        const COMMENT_ID = 'commentId';
        const TIME = 'time';
        const COLLECTION = 'collection';
        const USER_ID = 'userId';
        const PAGE_TOKEN = 'pageToken';
        const ORDER = 'orderBy';
        const SORT = 'sortOrder';
        const ACITIVITY_ID = 'activityId';
        const INFO = 'info';
        const GIVEN_NAME = 'givenName';
        const FAMILY_NAME = 'familyName';
        const STREET = 'street';
        const PHONE_NUMBER = 'phoneNumber';
        const CITY = 'city';
        const POST_CODE = 'postCode';
        const COUNTRY = 'country';
        const NOTES = 'notes';
        const EMAIL = 'email';
        const PRIMARY = 'primary';
        const DEFAULT_VALUE = 'default';
        const VERSION_THREE = '3.0';
        const VERSION_TWO = '2';
        const ME = 'me';
        const PUBLIC_DATA = 'public';
        const ALL = '~all';

        protected $_token = NULL;
        protected $_maxResult = NULL;
        protected $_headers = array(self::FORM_HEADER, self::CONTENT_TYPE);
        protected $_meta = array();
        protected $_developerId = NULL;
        protected $_etag = NULL;
        protected $_apiKey = NULL;
        protected $_query = array();

        public function getMeta() {
            return $this->_meta;
        }

        public function isXml($xml) {
            Eden_Google_Error::i()->argument(1, 'string', 'array', 'object', 'null');
            if (is_array($xml) || is_null($xml)) {
                return false;
            }libxml_use_internal_errors(true);
            $doc = new DOMDocument('1.0', 'utf-8');
            $doc->loadXML($xml);
            $errors = libxml_get_errors();
            return empty($errors);
        }

        public function isJson($string) {
            Eden_Google_Error::i()->argument(1, 'string');
            json_decode($string);
            return (json_last_error() == JSON_ERROR_NONE);
        }

        public function setXmlHeaders($developerId, $etag = false) {
            Eden_Google_Error::i()->argument(1, 'string', 'null')->argument(2, 'bool');
            if (is_null($developerId)) {
                $headers = array('application/x-www-form-urlencoded', 'Content-Type: application/atom+xml');
            }if (!is_null($developerId) && !$etag) {
                $headers = array('application/x-www-form-urlencoded', 'Content-Type: application/atom+xml', 'X-GData-Key: key=' . $developerId, 'GData-Version: 2');
            }if (is_null($developerId) && $etag) {
                $headers = array('application/x-www-form-urlencoded', 'Content-Type: application/atom+xml', 'If-Match: *');
            }return $headers;
        }

        public function formatToXml($query) {
            Eden_Google_Error::i()->argument(1, 'string', 'object');
            $xml = new DOMDocument();
            $xml->preserveWhiteSpace = false;
            $xml->formatOutput = true;
            $xml->loadXML($query);
            return $xml->saveXML();
        }

        protected function _accessKey($array) {
            foreach ($array as $key => $val) {
                if (is_array($val)) {
                    $array[$key] = $this->_accessKey($val);
                }if ($val == NULL || empty($val)) {
                    unset($array[$key]);
                }
            }return $array;
        }

        protected function _reset() {
            foreach ($this as $key => $value) {
                if (!is_array($this->$key)) {
                    if (preg_match('/^_/', $key)) {
                        if ($key != '_token') {
                            $this->$key = NULL;
                        }
                    }
                }
            }return $this;
        }

        protected function _customPost($url, array $query = array()) {
            $query[self::ACCESS_TOKEN] = $this->_token;
            if (is_array($query)) {
                $query = $this->_accessKey($query);
                $query = http_build_query($query);
            }$url = $url . '?' . $query;
            $curl = Eden_Curl::i()->verifyHost(false)->verifyPeer(false)->setUrl($url)->setPost(true)->setPostFields($query)->setHeaders($this->_headers);
            $response = $curl->getJsonResponse();
            $this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['headers'] = $this->_headers;
            $this->_meta['query'] = $query;
            unset($this->_query);
            return $response;
        }

        protected function _delete($url, array $query = array(), $etag = false) {
            if ($etag || !is_null($this->_developerId)) {
                $this->_headers = $this->setXmlHeaders($this->_developerId, $etag);
                $url = $url . '?' . self::ACCESS_TOKEN . '=' . $this->_token . '&v=3';
            } else {
                $url = $url . '?' . self::ACCESS_TOKEN . '=' . $this->_token;
            }$curl = Eden_Curl::i()->verifyHost(false)->verifyPeer(false)->setUrl($url)->setHeaders($this->_headers)->setCustomRequest('DELETE');
            $response = $curl->getResponse();
            $this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['headers'] = $this->_headers;
            unset($this->_query);
            if ($this->isJson($response)) {
                $response = json_decode($response, true);
            }if ($this->isXml($response)) {
                $response = simplexml_load_string($response);
            }return $response;
        }

        protected function _getResponse($url, array $query = array()) {
            $query[self::ACCESS_TOKEN] = $this->_token;
            if (!is_null($this->_developerId)) {
                $query[self::KEY] = $this->_developerId;
            }if (!is_null($this->_apiKey)) {
                $query[self::KEY] = $this->_apiKey;
            }$query = $this->_accessKey($query);
            $url = $url . '?' . http_build_query($query);
            $curl = Eden_Curl::i()->setUrl($url)->verifyHost(false)->verifyPeer(false)->setTimeout(60);
            $response = $curl->getResponse();
            $this->_meta['url'] = $url;
            $this->_meta['query'] = $query;
            $this->_meta['curl'] = $curl->getMeta();
            $this->_meta['response'] = $response;
            unset($this->_query);
            if ($this->isXml($response)) {
                return $response = simplexml_load_string($response);
            }if ($this->isJson($response)) {
                return $response = json_decode($response, true);
            }if (base64_decode($response, true)) {
                return $response;
            } else {
                return '<img src="data:image/jpeg;base64,' . base64_encode($response) . '" />';
            }
        }

        protected function _patch($url, array $query = array()) {
            $url = $url . '?' . self::ACCESS_TOKEN . '=' . $this->_token;
            $query = $this->_accessKey($query);
            $query = json_encode($query);
            $curl = Eden_Curl::i()->verifyHost(false)->verifyPeer(false)->setUrl($url)->setPost(true)->setPostFields($query)->setHeaders($this->_headers)->setCustomRequest('PATCH');
            $response = $curl->getJsonResponse();
            $this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['headers'] = $this->_headers;
            $this->_meta['query'] = $query;
            unset($this->_query);
            return $response;
        }

        protected function _post($url, $query, $etag = false) {
            if (is_array($query)) {
                $query = $this->_accessKey($query);
                $query = json_encode($query);
                $url = $url . '?' . self::ACCESS_TOKEN . '=' . $this->_token;
            }if ($this->isXml($query)) {
                $this->_headers = $this->setXmlHeaders($this->_developerId, $etag);
                $query = $this->formatToXml($query);
                $url = $url . '?' . self::ACCESS_TOKEN . '=' . $this->_token . '&alt=json';
            }$curl = Eden_Curl::i()->verifyHost(false)->verifyPeer(false)->setUrl($url)->setPost(true)->setPostFields($query)->setHeaders($this->_headers);
            $response = $curl->getResponse();
            $this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['headers'] = $this->_headers;
            $this->_meta['query'] = $query;
            unset($this->_query);
            if ($this->isJson($response)) {
                return $response = json_decode($response, true);
            }if ($this->isXml($response)) {
                return $response = simplexml_load_string($response);
            }return $response;
        }

        protected function _put($url, $query, $etag = false) {
            if (is_array($query)) {
                $query = $this->_accessKey($query);
                $query = json_encode($query);
                $url = $url . '?' . self::ACCESS_TOKEN . '=' . $this->_token;
            }if ($this->isXml($query)) {
                $this->_headers = $this->setXmlHeaders($this->_developerId, $etag);
                $query = $this->formatToXml($query);
                $url = $url . '?' . self::ACCESS_TOKEN . '=' . $this->_token;
            }if (is_string($query)) {
                $query = file_get_contents($query);
                $headers = array();
                $headers[] = 'Content-Length: ' . strlen($query);
                $headers[] = 'Content-Transfer-Encoding: base64';
                $this->_headers = $headers;
                $url = $url . '&' . self::ACCESS_TOKEN . '=' . $this->_token;
            }$fh = fopen('php://memory', 'rw');
            fwrite($fh, $query);
            rewind($fh);
            $curl = Eden_Curl::i()->verifyHost(false)->verifyPeer(false)->setHeaders($this->_headers)->setPut(true)->setUrl($url)->setInFile($fh)->setInFileSize(strlen($query));
            $response = $curl->getResponse();
            $this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['headers'] = $this->_headers;
            $this->_meta['query'] = $query;
            unset($this->_query);
            if ($this->isJson($response)) {
                return $response = json_decode($response, true);
            }if ($this->isXml($response)) {
                return $response = simplexml_load_string($response);
            }return $response;
        }

    }

}
/* Eden_Google_Oauth */
if (!class_exists('Eden_Google_Oauth')) {

    class Eden_Google_Oauth extends Eden_Oauth2_Client {

        const REQUEST_URL = 'https://accounts.google.com/o/oauth2/auth';
        const ACCESS_URL = 'https://accounts.google.com/o/oauth2/token';
        const SCOPE_ANALYTICS = 'https://www.googleapis.com/auth/analytics.readonly';
        const SCOPE_BASE = 'https://www.google.com/base/feeds/';
        const SCOPE_BUZZ = 'https://www.googleapis.com/auth/buzz';
        const SCOPE_BOOK = 'https://www.google.com/books/feeds/';
        const SCOPE_BLOGGER = 'https://www.blogger.com/feeds/';
        const SCOPE_CALENDAR = 'https://www.google.com/calendar/feeds/';
        const SCOPE_CONTACTS = 'https://www.google.com/m8/feeds/';
        const SCOPE_CHROME = 'https://www.googleapis.com/auth/chromewebstore.readonly';
        const SCOPE_DOCUMENTS = 'https://docs.google.com/feeds/';
        const SCOPE_DRIVE = 'https://www.googleapis.com/auth/drive';
        const SCOPE_FINANCE = 'https://finance.google.com/finance/feeds/';
        const SCOPE_GMAIL = 'https://mail.google.com/mail/feed/atom';
        const SCOPE_HEALTH = 'https://www.google.com/health/feeds/';
        const SCOPE_H9 = 'https://www.google.com/h9/feeds/';
        const SCOPE_MAPS = 'https://maps.google.com/maps/feeds/';
        const SCOPE_MODERATOR = 'https://www.googleapis.com/auth/moderator';
        const SCOPE_OPENSOCIAL = 'https://www-opensocial.googleusercontent.com/api/people/';
        const SCOPE_ORKUT = 'https://www.googleapis.com/auth/orkut';
        const SCOPE_PLUS = 'https://www.googleapis.com/auth/plus.me';
        const SCOPE_PICASA = 'https://picasaweb.google.com/data/';
        const SCOPE_SIDEWIKI = 'https://www.google.com/sidewiki/feeds/';
        const SCOPE_SITES = 'https://sites.google.com/feeds/';
        const SCOPE_SREADSHEETS = 'https://spreadsheets.google.com/feeds/';
        const SCOPE_TASKS = 'https://www.googleapis.com/auth/tasks';
        const SCOPE_SHORTENER = 'https://www.googleapis.com/auth/urlshortener';
        const SCOPE_WAVE = 'http://wave.googleusercontent.com/api/rpc';
        const SCOPE_WEBMASTER = 'https://www.google.com/webmasters/tools/feeds/';
        const SCOPE_YOUTUBE = 'https://gdata.youtube.com';

        protected $_apiKey = NULL;
        protected $_scopes = array('analytics' => self::SCOPE_ANALYTICS, 'base' => self::SCOPE_BASE, 'buzz' => self::SCOPE_BUZZ, 'book' => self::SCOPE_BOOK, 'blogger' => self::SCOPE_BLOGGER, 'calendar' => self::SCOPE_CALENDAR, 'contacts' => self::SCOPE_CONTACTS, 'chrome' => self::SCOPE_CHROME, 'documents' => self::SCOPE_DOCUMENTS, 'drive' => self::SCOPE_DRIVE, 'finance' => self::SCOPE_FINANCE, 'gmail' => self::SCOPE_GMAIL, 'health' => self::SCOPE_HEALTH, 'h9' => self::SCOPE_H9, 'maps' => self::SCOPE_MAPS, 'moderator' => self::SCOPE_MODERATOR, 'opensocial' => self::SCOPE_OPENSOCIAL, 'orkut' => self::SCOPE_ORKUT, 'plus' => self::SCOPE_PLUS, 'picasa' => self::SCOPE_PICASA, 'sidewiki' => self::SCOPE_SIDEWIKI, 'sites' => self::SCOPE_SITES, 'spreadsheets' => self::SCOPE_SREADSHEETS, 'tasks' => self::SCOPE_TASKS, 'shortener' => self::SCOPE_SHORTENER, 'wave' => self::SCOPE_WAVE, 'webmaster' => self::SCOPE_WEBMASTER, 'youtube' => self::SCOPE_YOUTUBE);

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($clientId, $clientSecret, $redirect, $apiKey = NULL) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string', 'null');
            $this->_apiKey = $apiKey;
            parent::__construct($clientId, $clientSecret, $redirect, self::REQUEST_URL, self::ACCESS_URL);
        }

        public function getLoginUrl($scope = NULL, $display = NULL) {
            Eden_Google_Error::i()->argument(1, 'string', 'array', 'null')->argument(2, 'string', 'array', 'null');
            if (is_string($scope) && isset($this->_scopes[$scope])) {
                $scope = $this->_scopes[$scope];
            } else if (is_array($scope)) {
                foreach ($scope as $i => $key) {
                    if (is_string($key) && isset($this->_scopes[$key])) {
                        $scope[$i] = $this->_scopes[$key];
                    }
                }
            }return parent::getLoginUrl($scope, $display);
        }

    }

}
/* Eden_Google_Analytics */
if (!class_exists('Eden_Google_Analytics')) {

    class Eden_Google_Analytics extends Eden_Google_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function management() {
            return Eden_Google_Analytics_Management::i($this->_token);
        }

        public function reporting() {
            return Eden_Google_Analytics_Reporting::i($this->_token);
        }

        public function multiChannel() {
            return Eden_Google_Analytics_Multichannel::i($this->_token);
        }

    }

}
/* Eden_Google_Calendar */
if (!class_exists('Eden_Google_Calendar')) {

    class Eden_Google_Calendar extends Eden_Google_Base {

        const URL_CALENDAR_COLOR = 'https://www.googleapis.com/calendar/v3/colors';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function acl() {
            return Eden_Google_Calendar_Acl::i($this->_token);
        }

        public function calendars() {
            return Eden_Google_Calendar_Calendars::i($this->_token);
        }

        public function getColors() {
            return $this->_getResponse(self::URL_CALENDAR_COLOR);
        }

        public function event() {
            return Eden_Google_Calendar_Event::i($this->_token);
        }

        public function freebusy() {
            return Eden_Google_Calendar_Freebusy::i($this->_token);
        }

        public function lists() {
            return Eden_Google_Calendar_List::i($this->_token);
        }

        public function settings() {
            return Eden_Google_Calendar_Settings::i($this->_token);
        }

    }

}
/* Eden_Google_Contacts */
if (!class_exists('Eden_Google_Contacts')) {

    class Eden_Google_Contacts extends Eden_Google_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function batch() {
            return Eden_Google_Contacts_Batch::i($this->_token);
        }

        public function data() {
            return Eden_Google_Contacts_Data::i($this->_token);
        }

        public function groups() {
            return Eden_Google_Contacts_Groups::i($this->_token);
        }

        public function photo() {
            return Eden_Google_Contacts_Photo::i($this->_token);
        }

    }

}
/* Eden_Google_Drive */
if (!class_exists('Eden_Google_Drive')) {

    class Eden_Google_Drive extends Eden_Google_Base {

        const URL_DRIVE_ABOUT = 'https://www.googleapis.com/drive/v2/about';
        const URL_DRIVE_APPS = 'hhttps://www.googleapis.com/drive/v2/apps';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function changes() {
            return Eden_Google_Drive_Changes::i($this->_token);
        }

        public function children() {
            return Eden_Google_Drive_Children::i($this->_token);
        }

        public function files() {
            return Eden_Google_Drive_Files::i($this->_token);
        }

        public function getAbout() {
            return $this->_getResponse(self::URL_DRIVE_ABOUT);
        }

        public function getApps() {
            return $this->_getResponse(self::URL_DRIVE_APPS);
        }

        public function parents() {
            return Eden_Google_Drive_Parent::i($this->_token);
        }

        public function permissions() {
            return Eden_Google_Drive_Permissions::i($this->_token);
        }

        public function revisions() {
            return Eden_Google_Drive_Revisions::i($this->_token);
        }

    }

}
/* Eden_Google_Maps */
if (!class_exists('Eden_Google_Maps')) {

    class Eden_Google_Maps extends Eden_Google_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function direction() {
            return Eden_Google_Maps_Direction::i($this->_token);
        }

        public function distance() {
            return Eden_Google_Maps_Distance::i($this->_token);
        }

        public function elevation() {
            return Eden_Google_Maps_Elevation::i($this->_token);
        }

        public function geocoding() {
            return Eden_Google_Maps_Geocoding::i($this->_token);
        }

        public function image() {
            return Eden_Google_Maps_Image::i($this->_token);
        }

    }

}
/* Eden_Google_Plus */
if (!class_exists('Eden_Google_Plus')) {

    class Eden_Google_Plus extends Eden_Google_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function activity() {
            return Eden_Google_Plus_Activity::i($this->_token);
        }

        public function comment() {
            return Eden_Google_Plus_Comment::i($this->_token);
        }

        public function people() {
            return Eden_Google_Plus_People::i($this->_token);
        }

    }

}
/* Eden_Google_Shopping */
if (!class_exists('Eden_Google_Shopping')) {

    class Eden_Google_Shopping extends Eden_Google_Base {

        const RANGES = ':ranges';
        const REQUEST_URL = 'https://www.googleapis.com/shopping/search/v1/public/products';
        const NAME = 'name';
        const VALUE = 'value';
        const QUERY = 'q';
        const COUNTRY = 'country';
        const CURRENCY = 'currency';
        const RESTRICT_BY = 'restrictBy';
        const RANK_BY = 'rankBy';
        const CROWD_BY = 'crowdBy';
        const SPELLING_CHECK = 'spelling.enabled';
        const FACETS_ENABLED = 'facets.enabled';
        const FACETS_INCLUDE = 'facets.include';

        protected $_country = NULL;
        protected $_currency = NULL;
        protected $_restrictBy = array();
        protected $_rankBy = array();
        protected $_crowding = array();
        protected $_keyword = array();
        protected $_spellChecker = false;
        protected $_facet = false;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function addFacet($name, $value, $range = false) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string', 'int')->argument(3, 'bool');
            if (!$this->_facet) {
                $this->_facet = true;
            }if ($range) {
                $value = $value . self::RANGES;
            }$this->_facetItem[] = array(self::NAME => $name, self::VALUE => $value);
            return $this;
        }

        public function addKeyword($keyword) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_keyword[] = $keyword;
            return $this;
        }

        public function addRestriction($name, $value) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'array');
            $this->_restrictBy[] = array(self::NAME => $name, self::VALUE => implode('|', $value));
            return $this;
        }

        public function getResponse() {
            if (!empty($this->_restrictBy)) {
                foreach ($this->_restrictBy as $key => $restrict) {
                    $restrictBy[] = $restrict[self::NAME] . ':' . $restrict[self::VALUE];
                }
            }if (!empty($this->_rankBy)) {
                $order = $this->_rankBy[self::NAME] . ':' . $this->_rankBy[self::VALUE];
            }if (!empty($this->_crowding)) {
                $crowding = $this->_crowding[self::NAME] . ':' . $this->_crowding[self::VALUE];
            }if (!empty($this->_facetItem)) {
                foreach ($this->_facetItem as $key => $facet) {
                    $facets[] = $facet[self::NAME] . ':' . $facet[self::VALUE];
                }
            }$params = array(self::QUERY => implode('|', $this->_keyword), self::COUNTRY => $this->_country, self::CURRENCY => $this->_currency, self::RESTRICT_BY => (!isset($restrictBy)) ? NULL : implode(',', $restrictBy), self::RANK_BY => (!isset($order)) ? NULL : $order, self::CROWD_BY => (!isset($crowding)) ? NULL : $crowding, self::SPELLING_CHECK => ($this->_spellChecker) ? 'true' : 'false', self::FACETS_ENABLED => ($this->_facet) ? 'true' : 'false', self::FACETS_INCLUDE => (!isset($facets)) ? NULL : implode(',', $facets));
            return $this->_getResponse(self::REQUEST_URL, $params);
        }

        public function setCountry($country = 'US') {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_country = $country;
            return $this;
        }

        public function setCrowding($name, $occurrence) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'int');
            $this->_crowding = array(self::NAME => $name, self::VALUE => $occurrence);
            return $this;
        }

        public function setCurrency($currency = 'USD') {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_currency = $currency;
            return $this;
        }

        public function setFacet($value = true) {
            Eden_Google_Error::i()->argument(1, 'bool');
            $this->_facet = $value;
            return $this;
        }

        public function setOrder($name, $value = 'assending') {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_rankBy = array(self::NAME => $name, self::VALUE => $value);
            return $this;
        }

        public function setSpellChecker($value = true) {
            Eden_Google_Error::i()->argument(1, 'bool');
            $this->_spellChecker = $value;
            return $this;
        }

    }

}
/* Eden_Google_Shortener */
if (!class_exists('Eden_Google_Shortener')) {

    class Eden_Google_Shortener extends Eden_Google_Base {

        const GOOGLE_SHORTENER_ANALYTICS = 'https://www.googleapis.com/urlshortener/v1/url';
        const GOOGLE_SHORTENER_GET = 'https://www.googleapis.com/urlshortener/v1/url/history';
        const GOOGLE_SHORTENER_CREATE = 'https://www.googleapis.com/urlshortener/v1/url';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($key, $token) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_apiKey = $key;
            $this->_token = $token;
        }

        public function getList() {
            return $this->_getResponse(self::GOOGLE_SHORTENER_GET, $this->_query);
        }

        public function getAnalytics($url) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['shortUrl'] = $url;
            return $this->_getResponse(self::GOOGLE_SHORTENER_ANALYTICS, $this->_query);
        }

        public function createShortUrl($url) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['longUrl'] = $url;
            return $this->_post(self::GOOGLE_SHORTENER_CREATE, $this->_query);
        }

        public function setStartToken($startToken) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['start-token'] = $startToken;
            return $this;
        }

        public function setProjection($projection) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['projection'] = $projection;
            return $this;
        }

    }

}
/* Eden_Google_Youtube */
if (!class_exists('Eden_Google_Youtube')) {

    class Eden_Google_Youtube extends Eden_Google_Base {

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function activity() {
            return Eden_Google_Youtube_Activity::i($this->_token, $this->_developerId);
        }

        public function channel() {
            return Eden_Google_Youtube_Channel::i($this->_token);
        }

        public function comment() {
            return Eden_Google_Youtube_Comment::i($this->_token, $this->_developerId);
        }

        public function contacts() {
            return Eden_Google_Youtube_Contacts::i($this->_token, $this->_developerId);
        }

        public function favorites() {
            return Eden_Google_Youtube_Favorites::i($this->_token, $this->_developerId);
        }

        public function history() {
            return Eden_Google_Youtube_History::i($this->_token, $this->_developerId);
        }

        public function message() {
            return Eden_Google_Youtube_Message::i($this->_token, $this->_developerId);
        }

        public function playlist() {
            return Eden_Google_Youtube_Playlist::i($this->_token, $this->_developerId);
        }

        public function profile() {
            return Eden_Google_Youtube_Profile::i($this->_token, $this->_developerId);
        }

        public function ratings() {
            return Eden_Google_Youtube_Ratings::i($this->_token, $this->_developerId);
        }

        public function search() {
            return Eden_Google_Youtube_Search::i($this->_token);
        }

        public function subscription() {
            return Eden_Google_Youtube_Subscription::i($this->_token, $this->_developerId);
        }

        public function upload() {
            return Eden_Google_Youtube_Upload::i($this->_token, $this->_developerId);
        }

        public function video() {
            return Eden_Google_Youtube_Video::i($this->_token);
        }

    }

}
/* Eden_Google_Analytics_Management */
if (!class_exists('Eden_Google_Analytics_Management')) {

    class Eden_Google_Analytics_Management extends Eden_Google_Base {

        const URL_ANALYTICS_ACCOUNTS = 'https://www.googleapis.com/analytics/v3/management/accounts';
        const URL_ANALYTICS_WEBPROPERTIES = 'https://www.googleapis.com/analytics/v3/management/accounts/%s/webproperties';
        const URL_ANALYTICS_PROFILE = 'https://www.googleapis.com/analytics/v3/management/accounts/%s/webproperties/%s/profiles';
        const URL_ANALYTICS_GOALS = 'https://www.googleapis.com/analytics/v3/management/accounts/%s/webproperties/%s/profiles/%s/goals';
        const URL_ANALYTICS_SEGMENTS = 'https://www.googleapis.com/analytics/v3/management/segments';

        protected $_startIndex = NULL;
        protected $_maxResults = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function setStartIndex($startIndex) {
            Eden_Google_Error::i()->argument(1, 'integer');
            $this->_startIndex = $startIndex;
            return $this;
        }

        public function setMaxResults($maxResults) {
            Eden_Google_Error::i()->argument(1, 'integer');
            $this->_maxResults = $maxResults;
            return $this;
        }

        public function getAccounts() {
            $query = array(self::START_INDEX => $this->_startIndex, self::MAX_RESULTS => $this->_maxResults);
            return $this->_getResponse(self::URL_ANALYTICS_ACCOUNTS, $query);
        }

        public function getWebProperties($accountId = self::ALL) {
            Eden_Google_Error::i()->argument(1, 'string');
            $query = array(self::START_INDEX => $this->_startIndex, self::MAX_RESULTS => $this->_maxResults);
            return $this->_getResponse(sprintf(self::URL_ANALYTICS_WEBPROPERTIES, $accountId), $query);
        }

        public function getProfiles($accountId = self::ALL, $webPropertyId = self::ALL) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = array(self::START_INDEX => $this->_startIndex, self::MAX_RESULTS => $this->_maxResults);
            return $this->_getResponse(sprintf(self::URL_ANALYTICS_PROFILE, $accountId, $webPropertyId), $query);
        }

        public function getGoals($accountId = self::ALL, $webPropertyId = self::ALL, $profileId = self::ALL) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $query = array(self::START_INDEX => $this->_startIndex, self::MAX_RESULTS => $this->_maxResults);
            return $this->_getResponse(sprintf(self::URL_ANALYTICS_GOALS, $accountId, $webPropertyId, $profileId), $query);
        }

        public function getSegments() {
            $query = array(self::START_INDEX => $this->_startIndex, self::MAX_RESULTS => $this->_maxResults);
            return $this->_getResponse(self::URL_ANALYTICS_SEGMENTS, $query);
        }

    }

}
/* Eden_Google_Calendar_Acl */
if (!class_exists('Eden_Google_Calendar_Acl')) {

    class Eden_Google_Calendar_Acl extends Eden_Google_Base {

        const URL_CALENDAR_ACL_GET = 'https://www.googleapis.com/calendar/v3/calendars/%s/acl';
        const URL_CALENDAR_ACL_SPECIFIC = 'https://www.googleapis.com/calendar/v3/calendars/%s/acl/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function create($role, $type, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query[self::ROLE] = $role;
            $this->_query[self::SCOPE] = array(self::TYPE => $type);
            return $this->_post(sprintf(self::URL_CALENDAR_ACL_GET, $calendarId), $this->_query);
        }

        public function delete($ruleId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_CALENDAR_ACL_SPECIFIC, $calendarId, $ruleId));
        }

        public function getList($calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_CALENDAR_ACL_GET, $calendarId));
        }

        public function getSpecific($ruleId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_getResponse(sprintf(self::URL_CALENDAR_ACL_SPECIFIC, $calendarId, $ruleId));
        }

        public function setEtag($etag) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::ETAG] = $etag;
            return $this;
        }

        public function setId($id) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query[self::ID] = $id;
            return $this;
        }

        public function setKind($kind) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::KIND] = $kind;
            return $this;
        }

        public function setRoleToFreeBusyReader() {
            $this->_query[self::ROLE] = 'freeBusyReader';
            return $this;
        }

        public function setRoleToNone() {
            $this->_query[self::ROLE] = 'none';
            return $this;
        }

        public function setRoleToReader() {
            $this->_query[self::ROLE] = 'reader';
            return $this;
        }

        public function setRoleToWriter() {
            $this->_query[self::ROLE] = 'writer';
            return $this;
        }

        public function setRoleToOwner() {
            $this->_query[self::ROLE] = 'owner';
            return $this;
        }

        public function setType($type) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::TYPE] = $type;
            return $this;
        }

        public function update($ruleId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_put(sprintf(self::URL_CALENDAR_ACL_SPECIFIC, $calendarId, $ruleId), $this->_query);
        }

    }

}
/* Eden_Google_Calendar_Calendars */
if (!class_exists('Eden_Google_Calendar_Calendars')) {

    class Eden_Google_Calendar_Calendars extends Eden_Google_Base {

        const URL_CALENDAR_GET = 'https://www.googleapis.com/calendar/v3/calendars/%s';
        const URL_CALENDAR_CREATE = 'https://www.googleapis.com/calendar/v3/calendars';
        const URL_CALENDAR_CLEAR = 'https://www.googleapis.com/calendar/v3/calendars/%s/clear';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function clear($calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_post(sprintf(self::URL_CALENDAR_CLEAR, calendarId));
        }

        public function create($summary) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::SUMMARY] = $summary;
            return $this->_post(self::URL_CALENDAR_CREATE, $this->_query);
        }

        public function delete($calendarid = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_delete(sprintf(self::URL_CALENDAR_GET, $calendarId));
        }

        public function getCalendars($calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_CALENDAR_GET, $calendarId));
        }

        public function patch($calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_patch(sprintf(self::URL_CALENDAR_GET, $calendarId), $this->_query);
        }

        public function setDescription($description) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::DESCRIPTION] = $description;
            return $this;
        }

        public function setEtag($etag) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::ETAG] = $etag;
            return $this;
        }

        public function setId($id) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query[self::ID] = $id;
            return $this;
        }

        public function setKind($kind) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::KIND] = $kind;
            return $this;
        }

        public function setLocation($location) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::LOCATION] = $location;
            return $this;
        }

        public function setSummary($summary) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::SUMMARY] = $summary;
            return $this;
        }

        public function setTimeZone($timeZone) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::TIMEZONE] = $timeZone;
            return $this;
        }

        public function update($calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_put(sprintf(self::URL_CALENDAR_GET, $calendarId), $this->_query);
        }

    }

}
/* Eden_Google_Calendar_Color */
if (!class_exists('Eden_Google_Calendar_Color')) {

    class Eden_Google_Calendar_Color extends Eden_Google_Base {

        const URL_CALENDAR_COLOR = 'https://www.googleapis.com/calendar/v3/colors';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function getList() {
            return $this->_getResponse(self::URL_CALENDAR_COLOR);
        }

    }

}
/* Eden_Google_Calendar_Event */
if (!class_exists('Eden_Google_Calendar_Event')) {

    class Eden_Google_Calendar_Event extends Eden_Google_Base {

        const URL_CALENDAR_EVENT = 'https://www.googleapis.com/calendar/v3/calendars/%s/events';
        const URL_CALENDAR = 'https://www.googleapis.com/calendar/v3/calendars/%s/events/%s';
        const URL_CALENDAR_IMPORT = 'https://www.googleapis.com/calendar/v3/calendars/%s/events/import';
        const URL_CALENDAR_MOVE = 'https://www.googleapis.com/calendar/v3/calendars/%s/events/%s/move';
        const URL_QUICK_CREATE_EVENT = 'https://www.googleapis.com/calendar/v3/calendars/%s/events/quickAdd';
        const URL_CALENDAR_INSTANCES = 'https://www.googleapis.com/calendar/v3/calendars/%s/events/%s/instances';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function addAttendee($attendee) {
            Eden_Google_Error::i()->argument(1, 'string', 'array');
            if (!is_array($attendee)) {
                $attendee = array($attendee);
            }foreach ($attendee as $user) {
                $this->_query[self::ATTENDESS][] = array('email' => $user);
            }return $this;
        }

        public function create($summary, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query[self::SUMMARY] = $summary;
            return $this->_post(sprintf(self::URL_CALENDAR_EVENT, $calendarId), $this->_query);
        }

        public function delete($eventId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_CALENDAR, $calendarId, $eventId));
        }

        public function getEvent($calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'int', 'string');
            return $this->_getResponse(sprintf(self::URL_CALENDAR_EVENT, $calendarId));
        }

        public function getInstances($eventId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_getResponse(sprintf(self::URL_CALENDAR_INSTANCES, $calendarId, $eventId));
        }

        public function getSpecificEvent($eventId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_getResponse(sprintf(self::URL_CALENDAR, $calendarId, $eventId));
        }

        public function importEvent($start, $end, $importId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string', 'int')->argument(2, 'string', 'int')->argument(3, 'string')->argument(4, 'string');
            if (is_string($start)) {
                $start = strtotime($start);
            }if (is_string($end)) {
                $end = strtotime($end);
            }$end['dateTime'] = date('c', $end);
            $start['dateTime'] = date('c', $start);
            $this->_query[self::START] = $start['dateTime'] = date('c', $start);
            $this->_query[self::END] = $end['dateTime'] = date('c', $end);
            $this->_query[self::UID] = $importId;
            return $this->_post(sprintf(self::URL_CALENDAR_IMPORT, $calendarId), $this->_query);
        }

        public function moveEvent($destination, $eventId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query[self::DESTINATION] = $description;
            return $this->_customPost(sprintf(self::URL_CALENDAR_MOVE, $calendarId, $eventId), $this->_query);
        }

        public function patch($eventId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_patch(sprintf(self::URL_CALENDAR, $calendarId, $eventId), $this->_query);
        }

        public function quickCreate($text, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query[self::TEXT] = $text;
            return $this->_customPost(sprintf(self::URL_QUICK_CREATE_EVENT, $calendarId), $this->_query);
        }

        public function setColorId($colorId) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query[self::COLOR_ID] = $colorId;
            return $this;
        }

        public function setCreator($creator) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::CREATOR] = $creator;
            return $this;
        }

        public function setDescription($description) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::DESCRIPTION] = $description;
            return $this;
        }

        public function setEnd($end) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            if (is_string($end)) {
                $end = strtotime($end);
            }$this->_query[self::END]['dateTime'] = date('c', $end);
            return $this;
        }

        public function setKind($kind) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::KIND] = $kind;
            return $this;
        }

        public function setLocation($location) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::LOCATION] = $location;
            return $this;
        }

        public function setOrganizer($organizer) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::ORGANIZER] = $organizer;
            return $this;
        }

        public function setReminders($reminders) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::REMINDERS] = $reminders;
            return $this;
        }

        public function setStart($start) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            if (is_string($start)) {
                $start = strtotime($start);
            }$this->_query[self::START]['dateTime'] = date('c', $start);
            return $this;
        }

        public function setStatus($status) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::STATUS] = $status;
            return $this;
        }

        public function update($eventId, $calendarId = self::PRIMARY) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_put(sprintf(self::URL_CALENDAR, $calendarId, $eventId), $this->_query);
        }

    }

}
/* Eden_Google_Calendar_Freebusy */
if (!class_exists('Eden_Google_Calendar_Freebusy')) {

    class Eden_Google_Calendar_Freebusy extends Eden_Google_Base {

        const URL_CALENDAR_FREEBUSY = 'https://www.googleapis.com/calendar/v3/freeBusy';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function query($startTime, $endTime) {
            Eden_Google_Error::i()->argument(1, 'string', 'int')->argument(2, 'string', 'int');
            if (is_string($startTime)) {
                $startTime = strtotime($startTime);
            }if (is_string($endTime)) {
                $endTime = strtotime($endTime);
            }$this->_query[self::TIMEMIN] = $startTime;
            $this->_query[self::TIMEMAX] = $endTime;
            return $this->_post(self::URL_CALENDAR_FREEBUSY, $this->_query);
        }

        public function setCalendarExpansionMax($calendarExpansionMax) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query[self::CALENDAR_EXPANSION] = $calendarExpansionMax;
            return $this;
        }

        public function setGroupExpansionMax($groupExpansionMax) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query[self::GROUP_EXPANSION] = $groupExpansionMax;
            return $this;
        }

        public function setItem($item) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query[self::ITEMS] = array(self::ID => $item);
            return $this;
        }

    }

}
/* Eden_Google_Calendar_List */
if (!class_exists('Eden_Google_Calendar_List')) {

    class Eden_Google_Calendar_List extends Eden_Google_Base {

        const URL_CALENDAR_LIST = 'https://www.googleapis.com/calendar/v3/users/me/calendarList';
        const URL_CALENDAR_GET = 'https://www.googleapis.com/calendar/v3/users/me/calendarList/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function create($id) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::ID] = $id;
            return $this->_post(self::URL_CALENDAR_LIST, $this->_query);
        }

        public function delete($calendarId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_delete(sprintf(self::URL_CALENDAR_GET, $calendarId));
        }

        public function getCalendar($calendarId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_CALENDAR_GET, $calendarId));
        }

        public function getList() {
            return $this->_getResponse(self::URL_CALENDAR_LIST, $this->_query);
        }

        public function patch($calendarId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_patch(sprintf(self::URL_CALENDAR_GET, $calendarId), $this->_query);
        }

        public function setAccessRole($accessRole) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[se::ACCESS_ROLE] = $accessRole;
            return $this;
        }

        public function setColorId($colorId) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query[self::COLOR_ID] = $colorId;
            return $this;
        }

        public function setDefaultReminders($defaultReminders) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::DEFAULT_REMINDERS] = $defaultReminders;
            return $this;
        }

        public function setDescription($description) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::DESCRIPTION] = $description;
            return $this;
        }

        public function setEtag($etag) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::ETAG] = $etag;
            return $this;
        }

        public function setHidden() {
            $this->_query[self::HIDDEN] = true;
            return $this;
        }

        public function setId($id) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query[self::ID] = $id;
            return $this;
        }

        public function setKind($kind) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::KIND] = $kind;
            return $this;
        }

        public function setLocation($location) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::LOCATION] = $location;
            return $this;
        }

        public function setMaxResults($maxResults) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query[self::MAX_RESULTS] = $maxResults;
            return $this;
        }

        public function setSelected() {
            $this->_query[self::SELECTED] = true;
            return $this;
        }

        public function setSummary($summary) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::SUMMARY] = $summary;
            return $this;
        }

        public function setSummaryOverride($summaryOverride) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::SUMMARY_OVERRIDE] = $summaryOverride;
            return $this;
        }

        public function setTimeZone($timeZone) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::TIMEZONE] = $timeZone;
            return $this;
        }

        public function update($calendarId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_put(sprintf(self::URL_CALENDAR_GET, $calendarId), $this->_query);
        }

    }

}
/* Eden_Google_Contacts_Batch */
if (!class_exists('Eden_Google_Contacts_Batch')) {

    class Eden_Google_Contacts_Batch extends Eden_Google_Base {

        const URL_CONTACTS_GROUPS_LIST = 'https://www.google.com/m8/feeds/groups/%s/full';
        const URL_CONTACTS_GROUPS_GET = 'https://www.google.com/m8/feeds/groups/%s/full/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function getList($userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::VERSION] = self::VERSION_THREE;
            return $this->_getResponse(sprintf(self::URL_CONTACTS_GROUPS_LIST, $userEmail), $this->_query);
        }

        public function create($title, $description, $info, $userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            $parameters = array(self::TITLE => $title, self::DESCRIPTION => $description, self::INFO => $info);
            $query = Eden_Template::i()->set($parameters)->parsePHP('<?xml version=\'1.0\' encoding=\'utf-8\'?>
<atom:entry xmlns:atom=\'http://www.w3.org/2005/Atom\' xmlns:gd=\'http://schemas.google.com/g/2005\'>
<atom:category scheme="http://schemas.google.com/g/2005#kind" term="http://schemas.google.com/contact/2008#group"/>
  <atom:title type="text"><?php echo $title; ?></atom:title>
  <gd:extendedProperty name="<?php echo $description; ?>">
    <info><?php echo $info; ?></info>
  </gd:extendedProperty>
</atom:entry>', true);
            return $this->_post(sprintf(self::URL_CONTACTS_GROUPS_LIST, $userEmail), $query);
        }

        public function delete($groupId, $userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_CONTACTS_GROUPS_GET, $userEmail, $groupId), true);
        }

    }

}
/* Eden_Google_Contacts_Data */
if (!class_exists('Eden_Google_Contacts_Data')) {

    class Eden_Google_Contacts_Data extends Eden_Google_Base {

        const URL_CONTACTS_LIST = 'https://www.google.com/m8/feeds/contacts/%s/full';
        const URL_CONTACTS_GET = 'https://www.google.com/m8/feeds/contacts/%s/full/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function getList($userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $query = array(self::VERSION => self::VERSION_THREE, self::RESPONSE => self::JSON_FORMAT);
            return $this->_getResponse(sprintf(self::URL_CONTACTS_LIST, $userEmail), $query);
        }

        public function getSpecific($contactId, $userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = array(self::VERSION => self::VERSION_THREE, self::RESPONSE => self::JSON_FORMAT);
            return $this->_getResponse(sprintf(self::URL_CONTACTS_GET, $userEmail, $contactId), $query);
        }

        public function create($givenName, $familyName, $phoneNumber, $city, $street, $postCode, $country, $notes, $email, $userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string')->argument(5, 'string')->argument(6, 'string')->argument(7, 'string')->argument(8, 'string')->argument(9, 'string')->argument(10, 'string');
            $query = Eden_Template::i()->set(self::GIVEN_NAME, $givenName)->set(self::FAMILY_NAME, $familyName)->set(self::PHONE_NUMBER, $phoneNumber)->set(self::CITY, $city)->set(self::STREET, $street)->set(self::POST_CODE, $postCode)->set(self::COUNTRY, $country)->set(self::NOTES, $notes)->set(self::EMAIL, $email)->parsePHP('<atom:entry xmlns:atom=\'http://www.w3.org/2005/Atom\' xmlns:gd=\'http://schemas.google.com/g/2005\'>
<atom:category scheme=\'http://schemas.google.com/g/2005#kind\' term=\'http://schemas.google.com/contact/2008#contact\'/>
	<gd:name>
     <gd:givenName><?php echo $givenName; ?></gd:givenName>
     <gd:familyName><?php echo $familyName; ?></gd:familyName>
     <gd:fullName><?php echo $fullName; ?></gd:fullName>
  </gd:name>
  <atom:content type=\'text\'><?php echo $notes; ?></atom:content>
  <gd:email rel=\'http://schemas.google.com/g/2005#work\'
    primary=\'true\'
    address=\'<?php echo $email; ?>\' displayName=\'<?php echo $fullName; ?>\'/> 
  <gd:email rel=\'http://schemas.google.com/g/2005#home\'
    address=\'<?php echo $email; ?>\'/>
  <gd:phoneNumber rel=\'http://schemas.google.com/g/2005#work\'
    primary=\'true\'>
    <?php echo $phoneNumber; ?>
  </gd:phoneNumber>
  <gd:phoneNumber rel=\'http://schemas.google.com/g/2005#home\'>
    <?php echo $phoneNumber; ?>
  </gd:phoneNumber>
  <gd:im address=\'<?php echo $email; ?>\'
    protocol=\'http://schemas.google.com/g/2005#GOOGLE_TALK\'
    primary=\'true\'
    rel=\'http://schemas.google.com/g/2005#home\'/>
  <gd:structuredPostalAddress
      rel=\'http://schemas.google.com/g/2005#work\'
      primary=\'true\'>
    <gd:city><?php echo $city; ?></gd:city>
    <gd:street><?php echo $street; ?></gd:street>
    <gd:region><?php echo $region; ?></gd:region>
    <gd:postcode><?php echo $postCode; ?></gd:postcode>
    <gd:country><?php echo $country; ?></gd:country>
    <gd:formattedAddress>
      <?php echo $street.\' \'.$city; ?>
    </gd:formattedAddress>
  </gd:structuredPostalAddress>
</atom:entry>', true);
            return $this->_post(sprintf(self::URL_CONTACTS_LIST, $userEmail), $query);
        }

        public function delete($contactId, $userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_CONTACTS_GET, $userEmail, $contactId), true);
        }

    }

}
/* Eden_Google_Contacts_Groups */
if (!class_exists('Eden_Google_Contacts_Groups')) {

    class Eden_Google_Contacts_Groups extends Eden_Google_Base {

        const URL_CONTACTS_GROUPS_LIST = 'https://www.google.com/m8/feeds/groups/%s/full';
        const URL_CONTACTS_GROUPS_GET = 'https://www.google.com/m8/feeds/groups/%s/full/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function getList($userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $query = array(self::VERSION => self::VERSION_THREE, self::RESPONSE => self::JSON_FORMAT);
            return $this->_getResponse(sprintf(self::URL_CONTACTS_CONTACTS_LIST, $userEmail), $query);
        }

        public function getSpecific($groudId, $userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = array(self::VERSION => self::VERSION_THREE, self::RESPONSE => self::JSON_FORMAT);
            return $this->_getResponse(sprintf(self::URL_CONTACTS_GROUPS_GET, $userEmail, $groupId), $query);
        }

        public function create($title, $description, $info, $userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            $query = Eden_Template::i()->set(self::TITLE, $title)->set(self::DESCRIPTION, $description)->set(self::INFO, $info)->parsePHP('<?xml version=\'1.0\' encoding=\'utf-8\'?>
<atom:entry xmlns:atom=\'http://www.w3.org/2005/Atom\' xmlns:gd=\'http://schemas.google.com/g/2005\'>
<atom:category scheme="http://schemas.google.com/g/2005#kind" term="http://schemas.google.com/contact/2008#group"/>
  <atom:title type="text"><?php echo $title; ?></atom:title>
  <gd:extendedProperty name="<?php echo $description; ?>">
    <info><?php echo $info; ?></info>
  </gd:extendedProperty>
</atom:entry>', true);
            return $this->_post(sprintf(self::URL_CONTACTS_GROUPS_LIST, $userEmail), $query);
        }

        public function delete($groupId, $userEmail = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_CONTACTS_GROUPS_GET, $userEmail, $groupId), true);
        }

    }

}
/* Eden_Google_Contacts_Photo */
if (!class_exists('Eden_Google_Contacts_Photo')) {

    class Eden_Google_Contacts_Photo extends Eden_Google_Base {

        const URL_CONTACTS_GET_IMAGE = 'https://www.google.com/m8/feeds/photos/media/%s/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function getImage($contactId, $userEmail = self::DAFAULT) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = array(self::VERSION => self::VERSION_THREE, self::RESPONSE => self::JSON_FORMAT);
            return $this->_getResponse(sprintf(self::URL_CONTACTS_GET_IMAGE, $userEmail, $contactId), $query);
        }

        public function delete($contactId, $userEmail = self::DAFAULT) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_CONTACTS_GET_IMAGE, $userEmail, contactId), true);
        }

    }

}
/* Eden_Google_Drive_Changes */
if (!class_exists('Eden_Google_Drive_Changes')) {

    class Eden_Google_Drive_Changes extends Eden_Google_Base {

        const URL_DRIVE_CHANGES_LIST = 'https://www.googleapis.com/drive/v2/changes';
        const URL_DRIVE_CHANGES_GET = 'https://www.googleapis.com/drive/v2/changes/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function getList() {
            return $this->_getResponse(self::URL_DRIVE_CHANGES_LIST);
        }

        public function getSpecific($changeId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_DRIVE_CHANGES_GET, $changeId));
        }

    }

}
/* Eden_Google_Drive_Children */
if (!class_exists('Eden_Google_Drive_Children')) {

    class Eden_Google_Drive_Children extends Eden_Google_Base {

        const URL_CHILDREN_LIST = 'https://www.googleapis.com/drive/v2/files/%s/children';
        const URL_CHILDREN_SPECIFIC = 'https://www.googleapis.com/drive/v2/files/%s/children/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function delete($folderId, $childId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_CHILDREN_SPECIFIC, $fileId, $childId));
        }

        public function getList($folderId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_CHANGES_LIST, $folderId));
        }

        public function getSpecific($folderId, $childId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_getResponse(sprintf(self::URL_CHILDREN_SPECIFIC, $fileId, $childId));
        }

        public function insert($folderId, $childId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = array(self::ID => $childId);
            return $this->_post(sprintf(self::URL_CHANGES_LIST, $folderId), $query);
        }

    }

}
/* Eden_Google_Drive_Files */
if (!class_exists('Eden_Google_Drive_Files')) {

    class Eden_Google_Drive_Files extends Eden_Google_Base {

        const URL_DRIVE_LIST = 'https://www.googleapis.com/drive/v2/files';
        const URL_DRIVE_GET = 'https://www.googleapis.com/drive/v2/files/%s';
        const URL_DRIVE_TRASH = 'https://www.googleapis.com/drive/v2/files/%s/trash';
        const URL_DRIVE_UNTRASH = 'https://www.googleapis.com/drive/v2/files/%s/untrash';
        const URL_DRIVE_TOUCH = 'https://www.googleapis.com/drive/v2/files/%s/touch';
        const URL_UPLOAD = 'https://www.googleapis.com/upload/drive/v2/files/%s?uploadType=media';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function copyFile($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_post(sprintf(self::URL_DRIVE_COPY, $fileId));
        }

        public function create($title, $mimeType, $data) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query[self::TITLE] = $title;
            $this->_query[self::MIME_TYPE] = $mimeType;
            $fileId = $this->_post(self::URL_DRIVE_LIST, $this->_query);
            if (isset($fileId['id']) && !empty($fileId['id'])) {
                return $this->upload($data, $fileId['id']);
            } else {
                return $fileId;
            }
        }

        public function delete($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_delete(sprintf(self::URL_DRIVE_GET, $fileId));
        }

        public function getList() {
            return $this->_getResponse(self::URL_DRIVE_LIST);
        }

        public function getSpecific($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_DRIVE_GET, $fileId));
        }

        public function patch($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_patch(sprintf(self::URL_DRIVE_GET, $fileId), $this->_query);
        }

        public function setDescription($description) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::DESCRIPTION] = $description;
            return $this;
        }

        public function setMimeType($mimeType) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::MIME_TYPE] = $mimeType;
            return $this;
        }

        public function setLastViewedDate($lastViewedDate) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            if (is_string($lastViewedByMeDate)) {
                $lastViewedByMeDate = strtotime($lastViewedByMeDate);
            }$this->_query[self::LAST_VIEW]['dateTime'] = date('c', $lastViewedByMeDate);
            return $this;
        }

        public function setModifiedDate($modifiedDate) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            if (is_string($modifiedDate)) {
                $modifiedDate = strtotime($modifiedDate);
            }$this->_query[self::MODIFIED_DATE]['dateTime'] = date('c', $modifiedDate);
            return $this;
        }

        public function setOcrLanguage($ocrLanguage) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::OCR_LANGUAGE] = $ocrLanguage;
            return $this;
        }

        public function setSourceLanguage($sourceLanguage) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::SOURCE_LANGUAGE] = $sourceLanguage;
            return $this;
        }

        public function setTargetLanguage($targetLanguage) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::TARGET_LANGUAGE] = $targetLanguage;
            return $this;
        }

        public function setTimedTextLanguage($timedTextLanguage) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::TEXT_LANGUAGE] = $timedTextLanguageE;
            return $this;
        }

        public function setTimedTextTrackName($timedTextTrackName) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::TEXT_TRACKNAME] = $timedTextTrackName;
            return $this;
        }

        public function setTitle($title) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::TITLE] = $title;
            return $this;
        }

        public function convert() {
            $this->_query[self::CONVERT] = true;
            return $this;
        }

        public function setToNewRevision() {
            $this->_query[self::NEW_REVISION] = true;
            return $this;
        }

        public function setToOcr() {
            $this->_query[self::OCR] = true;
            return $this;
        }

        public function setToPinned() {
            $this->_query[self::PINNED] = true;
            return $this;
        }

        public function trash($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_post(sprintf(self::URL_DRIVE_TRASH, $fileId));
        }

        public function touchFile($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_post(sprintf(self::URL_DRIVE_TOUCH, $fileId));
        }

        public function untrash() {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_post(sprintf(self::URL_DRIVE_UNTRASH, $fileId));
        }

        public function update($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_post(sprintf(self::URL_DRIVE_GET, $fileId), $this->_query);
        }

        public function upload($data, $id) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_put(sprintf(self::URL_UPLOAD, $id), $data);
        }

    }

}
/* Eden_Google_Drive_Parent */
if (!class_exists('Eden_Google_Drive_Parent')) {

    class Eden_Google_Drive_Parent extends Eden_Google_Base {

        const URL_PARENT_LIST = 'https://www.googleapis.com/drive/v2/files/%s/parents';
        const URL_PARENT_GET = 'https://www.googleapis.com/drive/v2/files/%s/parents/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function delete($fileId, $parentId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_PARENT_GET, $fileId, $parentId));
        }

        public function setChildLink($childLink) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_childLink = $childLink;
            return $this;
        }

        public function getList($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_PARENT_LIST, $fileId));
        }

        public function getSpecific($fileId, $parentId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_getResponse(sprintf(self::URL_PARENT_GET, $fileId, $parentId));
        }

        public function insert($fileId, $parentId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = array(self::ID => $parentId);
            return $this->_post(sprintf(self::URL_PARENT_LIST, $fileId), $query);
        }

    }

}
/* Eden_Google_Drive_Permissions */
if (!class_exists('Eden_Google_Drive_Permissions')) {

    class Eden_Google_Drive_Permissions extends Eden_Google_Base {

        const URL_PERMISSIONS_LIST = 'https://www.googleapis.com/drive/v2/files/%s/permissions';
        const URL_PERMISSIONS_GET = 'https://www.googleapis.com/drive/v2/files/%s/permissions/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function delete($fileId, $permissionId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_PERMISSIONS_GET, $fileId, $permissionId));
        }

        public function getList($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_PERMISSIONS_LIST, $fileId));
        }

        public function getSpecific($fileId, $permissionId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_getResponse(sprintf(self::URL_PERMISSIONS_GET, $fileId, $permissionId));
        }

        public function insert($fileId, $role, $type, $value = 'me') {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            if (!in_array($role, array('owner', 'reader', 'writer'))) {
                Eden_Google_Error::i()->setMessage(Eden_Google_Error::INVALID_ROLE)->addVariable($role)->trigger();
            }if (!in_array($type, array('user', 'group', 'domain', 'anyone'))) {
                Eden_Google_Error::i()->setMessage(Eden_Google_Error::INVALID_TYPE)->addVariable($type)->trigger();
            }$this->_query[self::VALUE] = $value;
            $this->_query[self::ROLE] = $role;
            $this->_query[self::TYPE] = $type;
            return $this->_post(sprintf(self::URL_PERMISSIONS_LIST, $fileId), $this->_query);
        }

        public function patch($fileId, $permissionId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_patch(sprintf(self::URL_PERMISSIONS_GET, $fileId, $permissionId), $this->_query);
        }

        public function setName($name) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::NAME] = $name;
            return $this;
        }

        public function setRole($role) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::ROLE] = $role;
            return $this;
        }

        public function setType($type) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::TYPE] = $type;
            return $this;
        }

        public function setValue($value) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::VALUE] = $value;
            return $this;
        }

        public function setWithLink() {
            $this->_query[self::WITH_LINK] = true;
            return $this;
        }

        public function update($fileId, $permissionId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_put(sprintf(self::URL_PERMISSIONS_GET, $fileId, $permissionId), $this->_query);
        }

    }

}
/* Eden_Google_Drive_Revisions */
if (!class_exists('Eden_Google_Drive_Revisions')) {

    class Eden_Google_Drive_Revisions extends Eden_Google_Base {

        const URL_REVISIONS_LIST = 'https://www.googleapis.com/drive/v2/files/%s/revisions';
        const URL_REVISIONS_GET = 'https://www.googleapis.com/drive/v2/files/%s/revisions/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function delete($fileId, $revisionId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_REVISIONS_GET, $fileId, $revisionId));
        }

        public function getList($fileId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_REVISIONS_LIST, $fileId));
        }

        public function getSpecific($fileId, $revisionId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_getResponse(sprintf(self::URL_REVISIONS_GET, $fileId, $revisionId));
        }

        public function patch($fileId, $revisionId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_patch(sprintf(self::URL_PERMISSIONS_GET, $fileId, $revisionId), $this->_query);
        }

        public function setPinned() {
            $this->_query[self::PINNED] = true;
            return $this;
        }

        public function setPublishAuto() {
            $this->_query[self::PUBLICHED_AUTO] = true;
            return $this;
        }

        public function setPublished() {
            $this->_query[self::PUBLISHED] = true;
            return $this;
        }

        public function setPublishedLink($publishedLink) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::PUBLISHED_LINK] = $publishedLink;
            return $this;
        }

        public function setPublishedOutsideDomain() {
            $this->_query[self::OUTSIDE_DOMAIN] = true;
            return $this;
        }

        public function update($fileId, $revisionId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_put(sprintf(self::URL_PERMISSIONS_GET, $fileId, $revisionId), $this->_query);
        }

    }

}
/* Eden_Google_Maps_Direction */
if (!class_exists('Eden_Google_Maps_Direction')) {

    class Eden_Google_Maps_Direction extends Eden_Google_Base {

        const URL_MAP_DIRECTION = 'http://maps.googleapis.com/maps/api/directions/json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function avoidHighways() {
            $this->_query['avoid'] = 'highways';
            return $this;
        }

        public function avoidTolls() {
            $this->_query['avoid'] = 'tolls';
            return $this;
        }

        public function bicycling() {
            $this->_query['mode'] = 'bicycling';
            return $this;
        }

        public function driving() {
            $this->_query['mode'] = 'driving';
            return $this;
        }

        public function transit() {
            $this->_query['mode'] = 'transit';
            return $this;
        }

        public function walking() {
            $this->_query['mode'] = 'walking';
            return $this;
        }

        public function setLanguage($language) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query['language'] = $language;
            return $this;
        }

        public function setWaypoints($waypoint) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query['waypoint'] = $waypoint;
            return $this;
        }

        public function setRegion($region) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query['region'] = $region;
            return $this;
        }

        public function setUnitToImperial() {
            $this->_query['units'] = 'imperial';
            return $this;
        }

        public function setAlternatives() {
            $this->_query['alternatives'] = 'true';
            return $this;
        }

        public function setDepartureTime($departureTime) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            if (is_string($departureTime)) {
                $departureTime = strtotime($departureTime);
            }$this->_query['departureTime'] = $departureTime;
            return $this;
        }

        public function setArrivalTime($arrivalTime) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            if (is_string($arrivalTime)) {
                $arrivalTime = strtotime($arrivalTime);
            }$this->_query['arrivalTime'] = $arrivalTime;
            return $this;
        }

        public function getDirection($origin, $destination, $sensor = 'false') {
            Eden_Google_Error::i()->argument(1, 'string', 'int', 'float')->argument(2, 'string', 'int', 'float')->argument(3, 'string');
            $this->_query['origin'] = $origin;
            $this->_query['sensor'] = $sensor;
            $this->_query['destination'] = $destination;
            return $this->_getResponse(self::URL_MAP_DIRECTION, $this->_query);
        }

    }

}
/* Eden_Google_Maps_Distance */
if (!class_exists('Eden_Google_Maps_Distance')) {

    class Eden_Google_Maps_Distance extends Eden_Google_Base {

        const URL_MAP_DISTANCE = 'http://maps.googleapis.com/maps/api/distancematrix/json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function avoidHighways() {
            $this->_query['avoid'] = 'highways';
            return $this;
        }

        public function avoidTolls() {
            $this->_query['avoid'] = 'tolls';
            return $this;
        }

        public function bicycling() {
            $this->_query['mode'] = 'bicycling';
            return $this;
        }

        public function driving() {
            $this->_query['mode'] = 'driving';
            return $this;
        }

        public function walking() {
            $this->_query['mode'] = 'walking';
            return $this;
        }

        public function setLanguage($language) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query['language'] = $language;
            return $this;
        }

        public function setUnitToImperial() {
            $this->_query['units'] = 'imperial';
            return $this;
        }

        public function getResponse($origin, $destination, $sensor = 'false') {
            Eden_Google_Error::i()->argument(1, 'string', 'int', 'float')->argument(2, 'string', 'int', 'float')->argument(3, 'string');
            $this->_query['origin'] = $origin;
            $this->_query['sensor'] = $sensor;
            $this->_query['destinations'] = $destination;
            return $this->_getResponse(self::URL_MAP_DISTANCE, $this->_query);
        }

    }

}
/* Eden_Google_Maps_Elevation */
if (!class_exists('Eden_Google_Maps_Elevation')) {

    class Eden_Google_Maps_Elevation extends Eden_Google_Base {

        const URL_MAP_ELEVATION = 'http://maps.googleapis.com/maps/api/elevation/json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function setPath($latitude, $longtitude) {
            Eden_Google_Error::i()->argument(1, 'string', 'int', 'float')->argument(2, 'string', 'int', 'float');
            $this->_query['path'] = $latitude . ',' . $longtitude;
            return $this;
        }

        public function setSamples($samples) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query['samples'] = $samples;
            return $this;
        }

        public function getResponse($location, $sensor = 'false') {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['locations'] = $location;
            $this->_query['sensor'] = $sensor;
            return $this->_getResponse(self::URL_MAP_ELEVATION, $this->_query);
        }

    }

}
/* Eden_Google_Maps_Geocoding */
if (!class_exists('Eden_Google_Maps_Geocoding')) {

    class Eden_Google_Maps_Geocoding extends Eden_Google_Base {

        const URL_MAP_GEOCODING = 'http://maps.googleapis.com/maps/api/geocode/json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function setBounds($bounds) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['bounds'] = $bounds;
            return $this;
        }

        public function setLanguage($language) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['language'] = $language;
            return $this;
        }

        public function setRegion($region) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['region'] = $region;
            return $this;
        }

        public function getResponse($address, $sensor = 'false') {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['address'] = $address;
            $this->_query['sensor'] = $sensor;
            return $this->_getResponse(self::URL_MAP_GEOCODING, $this->_query);
        }

    }

}
/* Eden_Google_Maps_Image */
if (!class_exists('Eden_Google_Maps_Image')) {

    class Eden_Google_Maps_Image extends Eden_Google_Base {

        const URL_MAP_IMAGE_STATIC = 'http://maps.googleapis.com/maps/api/staticmap';
        const URL_MAP_IMAGE_STREET = 'http://maps.googleapis.com/maps/api/streetview';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($apiKey) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_apiKey = $apiKey;
        }

        public function setScale($scale) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query['scale'] = $scale;
            return $this;
        }

        public function setFormat($format) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['format'] = $format;
            return $this;
        }

        public function setLanguage($language) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['language'] = $language;
            return $this;
        }

        public function setRegion($region) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['region'] = $region;
            return $this;
        }

        public function setMarkers($markers) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['markers'] = $markers;
            return $this;
        }

        public function setPath($path) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['path'] = $path;
            return $this;
        }

        public function setVisible($visible) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['visible'] = $visible;
            return $this;
        }

        public function setStyle($style) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query['style'] = $style;
            return $this;
        }

        public function setHeading($heading) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query['heading'] = $heading;
            return $this;
        }

        public function setFov($fov) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query['fov'] = $fov;
            return $this;
        }

        public function setPitch($pitch) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query['pitch'] = $pitch;
            return $this;
        }

        public function useRoadMap() {
            $this->_query['maptype'] = 'roadmap';
            return $this;
        }

        public function useSatelliteMap() {
            $this->_query['maptype'] = 'satellite';
            return $this;
        }

        public function useTerrainMap() {
            $this->_query['maptype'] = 'terrain';
            return $this;
        }

        public function useHybridMap() {
            $this->_query['maptype'] = 'hybrid';
            return $this;
        }

        public function getStaticMap($center, $zoom, $size, $sensor = 'false') {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            $this->_query['center'] = $center;
            $this->_query['zoom'] = $zoom;
            $this->_query['size'] = $size;
            $this->_query['sensor'] = $sensor;
            return $this->_getResponse(self::URL_MAP_IMAGE_STATIC, $this->_query);
        }

        public function getStreetMap($location, $size, $sensor = 'false') {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $this->_query['size'] = $size;
            $this->_query['location'] = $location;
            $this->_query['sensor'] = $sensor;
            return $this->_getResponse(self::URL_MAP_IMAGE_STREET, $this->_query);
        }

    }

}
/* Eden_Google_Plus_Activity */
if (!class_exists('Eden_Google_Plus_Activity')) {

    class Eden_Google_Plus_Activity extends Eden_Google_Base {

        const URL_ACTIVITY_LIST = 'https://www.googleapis.com/plus/v1/people/%s/activities/%s';
        const URL_ACTIVITY_GET = 'https://www.googleapis.com/plus/v1/activities/%s';
        const URL_ACTIVITY_SEARCH = 'https://www.googleapis.com/plus/v1/activities';

        protected $_pageToken = NULL;
        protected $_maxResults = NULL;
        protected $_orderBy = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function setPageToken($pageToken) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::PAGE_TOKEN] = $pageToken;
            return $this;
        }

        public function setMaxResults($maxResults) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query[self::MAX_RESULTS] = $maxResults;
            return $this;
        }

        public function orderByBest() {
            $this->_query[self::ORDER] = 'best';
            return $this;
        }

        public function orderByRecent() {
            $this->_query[self::ORDER] = 'recent';
            return $this;
        }

        public function getList($userId = self::ME) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_ACTIVITY_LIST, $userId, self::PUBLIC_DATA), $this->_query);
        }

        public function getSpecific($activityId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_ACTIVITY_GET, $activityId));
        }

        public function search($queryString) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query[self::QUERY_STRING] = $queryString;
            return $this->_getResponse(self::URL_ACTIVITY_SEARCH, $this->_query);
        }

    }

}
/* Eden_Google_Plus_Comment */
if (!class_exists('Eden_Google_Plus_Comment')) {

    class Eden_Google_Plus_Comment extends Eden_Google_Base {

        const URL_COMMENTS_LIST = 'https://www.googleapis.com/plus/v1/activities/%s/comments';
        const URL_COMMENTS_GET = 'https://www.googleapis.com/plus/v1/comments/%s';

        protected $_pageToken = NULL;
        protected $_maxResults = NULL;
        protected $_sortOrder = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function setPageToken($pageToken) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::PAGE_TOKEN] = $pageToken;
            return $this;
        }

        public function setMaxResults($maxResults) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query[self::MAX_RESULTS] = $maxResults;
            return $this;
        }

        public function descendingOrder() {
            $this->_query[self::SORT] = 'descending';
            return $this;
        }

        public function getList($activityId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_COMMENTS_LIST, $activityId), $this->_query);
        }

        public function getSpecific($commentId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_COMMENTS_GET, $commentId));
        }

    }

}
/* Eden_Google_Plus_People */
if (!class_exists('Eden_Google_Plus_People')) {

    class Eden_Google_Plus_People extends Eden_Google_Base {

        const URL_GET_USER = 'https://www.googleapis.com/plus/v1/people/%s';
        const URL_PEOPLE_SEARCH = 'https://www.googleapis.com/plus/v1/people';
        const URL_PEOPLE_ACTIVITY = 'https://www.googleapis.com/plus/v1/activities/%s/people/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function setPageToken($pageToken) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::PAGE_TOKEN] = $pageToken;
            return $this;
        }

        public function setMaxResults($maxResults) {
            Eden_Google_Error::i()->argument(1, 'int');
            $this->_query[self::MAX_RESULTS] = $maxResults;
            return $this;
        }

        public function getUserInfo($userId = self::ME) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_GET_USER, $userId));
        }

        public function search($queryString) {
            Eden_Google_Error::i()->argument(1, 'string', 'int');
            $this->_query[self::QUERY_STRING] = $queryString;
            return $this->_getResponse(self::URL_PEOPLE_SEARCH, $this->_query);
        }

        public function getActivityList($activityId, $collection) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            if (!in_array($collection, array('plusoners', 'resharers'))) {
                Eden_Google_Error::i()->setMessage(Eden_Google_Error::INVALID_COLLECTION)->addVariable($collection)->trigger();
            }$this->_query[self::ACTIVITY_ID] = $activityId;
            $this->_query[self::COLLECTION] = $collection;
            return $this->_getResponse(sprintf(self::URL_PEOPLE_ACTIVITY, $activityId, $collection), $this->_query);
        }

    }

}
/* Eden_Google_Youtube_Activity */
if (!class_exists('Eden_Google_Youtube_Activity')) {

    class Eden_Google_Youtube_Activity extends Eden_Google_Base {

        const URL_YOUTUBE_EVENT = 'https://gdata.youtube.com/feeds/api/users/%s/events';
        const URL_YOUTUBE_SUBTIVITY = 'https://gdata.youtube.com/feeds/api/users/%s/subtivity';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function getEvent($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $query = array(self::RESPONSE => self::JSON_FORMAT, self::VERSION => self::VERSION);
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_EVENT, $userId), $query);
        }

        public function getSubtivity($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $query = array(self::RESPONSE => self::JSON_FORMAT, self::VERSION => self::VERSION);
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_SUBTIVITY, $userId), $query);
        }

    }

}
/* Eden_Google_Youtube_Channel */
if (!class_exists('Eden_Google_Youtube_Channel')) {

    class Eden_Google_Youtube_Channel extends Eden_Google_Base {

        const URL_YOUTUBE_CHANNEL = 'https://gdata.youtube.com/feeds/api/channels';
        const URL_YOUTUBE_CHANNEL_FEEDS = 'https://gdata.youtube.com/feeds/api/channelstandardfeeds/%s';
        const URL_YOUTUBE_REGION = 'https://gdata.youtube.com/feeds/api/channelstandardfeeds/%s/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function setStartIndex($startIndex) {
            Eden_Google_Error::i()->argument(1, 'integer');
            $this->_query[self::START_INDEX] = $startIndex;
            return $this;
        }

        public function setMaxResults($maxResults) {
            Eden_Google_Error::i()->argument(1, 'integer');
            $this->_query[self::MAX_RESULTS] = $maxResults;
            return $this;
        }

        public function setToday() {
            $this->_query[self::TIME] = 'today';
            return $this;
        }

        public function setThisWeek() {
            $this->_query[self::TIME] = 'this_week';
            return $this;
        }

        public function setThisMonth() {
            $this->_query[self::TIME] = 'this_month';
            return $this;
        }

        public function setToAllTime() {
            $this->_query[self::TIME] = 'all_time';
            return $this;
        }

        public function search($queryString) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::QUERY] = $queryString;
            $this->_query[self::VERSION] = self::VERSION_TWO;
            return $this->_getResponse(self::URL_YOUTUBE_CHANNEL, $this->_query);
        }

        public function getChannelFeeds($feeds) {
            Eden_Google_Error::i()->argument(1, 'string');
            if (!in_array($feeds, array('most_viewed', 'most_subscribed'))) {
                Eden_Google_Error::i()->setMessage(Eden_Google_Error::INVALID_FEEDS_ONE)->addVariable($feeds)->trigger();
            }$this->_query[self::VERSION] = self::VERSION_TWO;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_CHANNEL_FEEDS, $feeds), $this->_query);
        }

        public function getChannelByRegion($regionId, $feeds) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            if (!in_array($feeds, array('most_viewed', 'most_subscribed'))) {
                Eden_Google_Error::i()->setMessage(Eden_Google_Error::INVALID_FEEDS_TWO)->addVariable($feeds)->trigger();
            }$this->_query[self::VERSION] = self::VERSION_TWO;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_REGION, $regionId, $feeds), $this->_query);
        }

    }

}
/* Eden_Google_Youtube_Comment */
if (!class_exists('Eden_Google_Youtube_Comment')) {

    class Eden_Google_Youtube_Comment extends Eden_Google_Base {

        const URL_YOUTUBE_GET_COMMENTS = 'https://gdata.youtube.com/feeds/api/videos/%s/comments';
        const URL_YOUTUBE_COMMENTS = 'https://gdata.youtube.com/feeds/api/videos/%s/comments/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function getList($videoId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_GET_COMMENTS, $videoId));
        }

        public function getSpecific($videoId, $commentId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_COMMENTS, $videoId, $commentId));
        }

        public function addComment($videoId, $comment) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = Eden_Template::i()->set(self::COMMENT, $comment)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
    xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <content><?php echo $comment; ?></content>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_GET_COMMENTS, $videoId), $query);
        }

        public function replyToComment($videoId, $commentId, $comment) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $query = Eden_Template::i()->set(self::COMMENT, $comment)->set(self::COMMENT_ID, $commentId)->set(self::VIDEO_ID, $videoId)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
    xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <link rel="http://gdata.youtube.com/schemas/2007#in-reply-to"
    type="application/atom+xml" 
    href="https://gdata.youtube.com/feeds/api/videos/<?php echo $videoId; ?>/comments/<?php echo $commentId; ?>"/>
  <content><?php echo $comment?></content>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_GET_COMMENTS, $videoId), $query);
        }

        public function delete($videoId, $commentId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_YOUTUBE_COMMENTS, $videoId, $commentId));
        }

    }

}
/* Eden_Google_Youtube_Contacts */
if (!class_exists('Eden_Google_Youtube_Contacts')) {

    class Eden_Google_Youtube_Contacts extends Eden_Google_Base {

        const URL_YOUTUBE_CONTACTS = 'https://gdata.youtube.com/feeds/api/users/%s/contacts';
        const URL_YOUTUBE_CONTACTS_GET = 'https://gdata.youtube.com/feeds/api/users/%s/contacts/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function getList($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_CONTACTS, $userId), $this->_query);
        }

        public function getSpecific($userName, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_CONTACTS_GET, $userId, $userName), $this->_query);
        }

        public function delete($userName, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_YOUTUBE_CONTACTS_GET, $userId, $userName));
        }

        public function addContacts($userName, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = Eden_Template::i()->set(self::USER_NAME, $userName)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns=\'http://www.w3.org/2005/Atom\'
       xmlns:yt=\'http://gdata.youtube.com/schemas/2007\'>
  <yt:username><?php echo $userName; ?></yt:username>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_CONTACTS, $userId), $query);
        }

        public function updateContacts($userName, $status, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            if (!in_array($status, array('accepted', 'rejected'))) {
                Eden_Google_Error::i()->setMessage(Eden_Google_Error::INVALID_STATUS)->addVariable($status)->trigger();
            }$query = Eden_Template::i()->set(self::STATUS, $status)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
    xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <status><?php echo $status; ?></status>
</entry>', true);
            return $this->_put(sprintf(self::URL_YOUTUBE_CONTACTS_GET, $userId, $userName), $query);
        }

    }

}
/* Eden_Google_Youtube_Favorites */
if (!class_exists('Eden_Google_Youtube_Favorites')) {

    class Eden_Google_Youtube_Favorites extends Eden_Google_Base {

        const URL_YOUTUBE_FAVORITES = 'https://gdata.youtube.com/feeds/api/users/%s/favorites';
        const URL_YOUTUBE_FAVORITES_GET = 'https://gdata.youtube.com/feeds/api/users/%s/favorites/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function getList($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_FAVORITES, $userId), $this->_query);
        }

        public function getSpecific($favoriteVideoId, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_FAVORITES_GET, $userId, $favoriteVideoId), $this->_query);
        }

        public function addFavorites($videoId, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = Eden_Template::i()->set(self::VIDEO_ID, $videoId)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom">
  <id><?php echo $videoId; ?></id>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_FAVORITES, $userId), $query);
        }

        public function removeFavorites($favoriteVideoId, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_YOUTUBE_FAVORITES_GET, $userId, $favoriteVideoId));
        }

    }

}
/* Eden_Google_Youtube_History */
if (!class_exists('Eden_Google_Youtube_History')) {

    class Eden_Google_Youtube_History extends Eden_Google_Base {

        const URL_YOUTUBE_HISTORY = 'https://gdata.youtube.com/feeds/api/users/default/watch_history';
        const URL_YOUTUBE_HISTORY_GET = 'https://gdata.youtube.com/feeds/api/users/default/watch_history/%s';
        const URL_YOUTUBE_HISTORY_CLEAR = 'https://gdata.youtube.com/feeds/api/users/default/watch_history/actions/clear';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function getList() {
            $this->_query[self::VERSION] = self::VERSION_TWO;
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_HISTORY), $this->_query);
        }

        public function deleteSpecific($historyId) {
            Eden_Google_Error::i()->argument(1, 'string');
            return $this->_delete(sprintf(self::URL_YOUTUBE_HISTORY_GET, $historyId));
        }

        public function clearHistory() {
            $query = $this->Eden_Google_Youtube_Block_Clear();
            return $this->_post(sprintf(self::URL_YOUTUBE_HISTORY_CLEAR), $query);
        }

    }

}
/* Eden_Google_Youtube_Message */
if (!class_exists('Eden_Google_Youtube_Message')) {

    class Eden_Google_Youtube_Message extends Eden_Google_Base {

        const URL_YOUTUBE_MESSAGE = 'https://gdata.youtube.com/feeds/api/users/%s/inbox';
        const URL_YOUTUBE_MESSAGE_GET = 'https://gdata.youtube.com/feeds/api/users/%s/inbox/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function getList($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_MESSAGE, $userId), $this->_query);
        }

        public function sendMessage($videoId, $summary, $userName) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $query = Eden_Template::i()->set(self::VIDEO_ID, $videoId)->set(self::SUMMARY, $summary)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
    xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <id><?php echo $videoId; ?></id>
  <summary><?php echo $summary; ?></summary>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_MESSAGE, $userName), $query);
        }

        public function delete($messageId, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_YOUTUBE_MESSAGE_GET, $userId, $messageId));
        }

    }

}
/* Eden_Google_Youtube_Playlist */
if (!class_exists('Eden_Google_Youtube_Playlist')) {

    class Eden_Google_Youtube_Playlist extends Eden_Google_Base {

        const URL_YOUTUBE_PLAYLIST = 'https://gdata.youtube.com/feeds/api/users/%s/playlists';
        const URL_YOUTUBE_PLAYLIST_UPDATE = 'https://gdata.youtube.com/feeds/api/users/%s/playlists/%s';
        const URL_YOUTUBE_PLAYLIST_DELETE = 'https://gdata.youtube.com/feeds/api/users/%s/playlists/%s';
        const URL_YOUTUBE_PLAYLIST_GET = 'https://gdata.youtube.com/feeds/api/playlists/%s';
        const URL_YOUTUBE_PLAYLIST_VIDEO = 'https://gdata.youtube.com/feeds/api/playlists/%s/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_developerId = $developerId;
            $this->_token = $token;
        }

        public function getList($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_PLAYLIST, $userId), $this->_query);
        }

        public function create($title, $summary, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $query = Eden_Template::i()->set(self::TITLE, $title)->set(self::SUMMARY, $summary)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
    xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <title type="text"><?php echo $title; ?></title>
  <summary><?php echo $summary; ?></summary>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_PLAYLIST, $userId), $query);
        }

        public function update($title, $summary, $playlistId, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            $query = Eden_Template::i()->set(self::TITLE, $title)->set(self::SUMMARY, $summary)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
    xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <title type="text"><?php echo $title; ?></title>
  <summary><?php echo $summary; ?></summary>
</entry>', true);
            return $this->_put(sprintf(self::URL_YOUTUBE_PLAYLIST_UPDATE, $userId, $playlistId), $query);
        }

        public function addVideo($videoId, $position, $playlistId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $query = Eden_Template::i()->set(self::VIDEO_ID, $videoId)->set(self::POSITION, $position)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom" xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <id><?php echo $videoId; ?></id>
  <yt:position><?php echo $position; ?></yt:position>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_PLAYLIST_GET, $playlistId), $query);
        }

        public function updateVideo($position, $playlistId, $entryId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            $query = Eden_Template::i()->set(self::POSITION, $position)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom" xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <id><?php echo $videoId; ?></id>
  <yt:position><?php echo $position; ?></yt:position>
</entry>', true);
            return $this->_put(sprintf(self::URL_YOUTUBE_PLAYLIST_VIDEO, $playlistId, $entryId), $query);
        }

        public function removeVideo($playlistId, $entryId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_YOUTUBE_PLAYLIST_VIDEO, $playlistId, $entryId));
        }

        public function delete($playlistId, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_YOUTUBE_PLAYLIST_DELETE, $userId, $playlistId));
        }

    }

}
/* Eden_Google_Youtube_Profile */
if (!class_exists('Eden_Google_Youtube_Profile')) {

    class Eden_Google_Youtube_Profile extends Eden_Google_Base {

        const URL_YOUTUBE_PROFILE = 'https://gdata.youtube.com/feeds/api/users/%s';
        const URL_YOUTUBE_UPLOADS = 'https://gdata.youtube.com/feeds/api/users/%s/uploads';
        const URL_YOUTUBE_GET = 'https://gdata.youtube.com/feeds/api/users/%s/uploads/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function getList($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_PROFILE, $userId), $this->_query);
        }

        public function getUserVideoUploads($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_UPLOADS, $userId), $this->_query);
        }

        public function getSpecificUserVideo($videoId, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_GET, $userId, $videoId), $this->_query);
        }

        public function activateAccount($userName, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = Eden_Template::i()->set(self::USER_NAME, $userName)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns=\'http://www.w3.org/2005/Atom\'
       xmlns:yt=\'http://gdata.youtube.com/schemas/2007\'>
  <yt:username><?php echo $userName; ?></yt:username>
</entry>', true);
            return $this->_put(sprintf(self::URL_YOUTUBE_PROFILE, $userId), $query);
        }

    }

}
/* Eden_Google_Youtube_Ratings */
if (!class_exists('Eden_Google_Youtube_Ratings')) {

    class Eden_Google_Youtube_Ratings extends Eden_Google_Base {

        const URL_YOUTUBE_RATINGS = 'https://gdata.youtube.com/feeds/api/videos/%s/ratings';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function addRating($videoId, $rating) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string', 'int');
            $query = Eden_Template::i()->set(self::RATINGS, $rating)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
       xmlns:gd="http://schemas.google.com/g/2005">
  <gd:rating value="<?php echo $ratings; ?>" min="1" max="5"/>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_RATINGS, $videoId), $query);
        }

        public function like($videoId) {
            Eden_Google_Error::i()->argument(1, 'string');
            $query = Eden_Template::i()->set(self::VALUE, self::LIKE)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
       xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <yt:rating value="<?php echo $value; ?>"/>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_RATINGS, $videoId), $query);
        }

        public function dislike($videoId) {
            Eden_Google_Error::i()->argument(1, 'string');
            $query = Eden_Template::i()->set(self::VALUE, self::DISLIKE)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
       xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <yt:rating value="<?php echo $value; ?>"/>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_RATINGS, $videoId), $query);
        }

    }

}
/* Eden_Google_Youtube_Search */
if (!class_exists('Eden_Google_Youtube_Search')) {

    class Eden_Google_Youtube_Search extends Eden_Google_Base {

        const URL_YOUTUBE_SEARCH = 'https://gdata.youtube.com/feeds/api/videos';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_token = $token;
        }

        public function setStart($start) {
            Eden_Google_Error::i()->argument(1, 'integer');
            $this->_query[self::START_INDEX] = $start;
            return $this;
        }

        public function setRange($range) {
            Eden_Google_Error::i()->argument(1, 'integer');
            $this->_query[self::MAX_RESULTS] = $range;
            return $this;
        }

        public function orderByRelevance() {
            $this->_query[self::ORDER_BY] = 'relevance';
            return $this;
        }

        public function orderByPublished() {
            $this->_query[self::ORDER_BY] = 'published';
            return $this;
        }

        public function orderByViewCount() {
            $this->_query[self::ORDER_BY] = 'viewCount';
            return $this;
        }

        public function orderByRating() {
            $this->_query[self::ORDER_BY] = 'rating';
            return $this;
        }

        public function getResponse($queryString) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::QUERY] = $queryString;
            $this->_query[self::VERSION] = self::VERSION_TWO;
            return $this->_getResponse(self::URL_YOUTUBE_SEARCH, $this->_queryquery);
        }

    }

}
/* Eden_Google_Youtube_Subscription */
if (!class_exists('Eden_Google_Youtube_Subscription')) {

    class Eden_Google_Youtube_Subscription extends Eden_Google_Base {

        const URL_YOUTUBE_SUBSCRIPTION = 'https://gdata.youtube.com/feeds/api/users/%s/subscriptions';
        const URL_YOUTUBE_NEW_SUBSCRIPTION = 'https://gdata.youtube.com/feeds/api/users/%s/newsubscriptionvideos';
        const URL_YOUTUBE_UNSUBSCRIPTION = 'https://gdata.youtube.com/feeds/api/users/%s/subscriptions/%s';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function getList($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_SUBSCRIPTION, $userId), $this->_query);
        }

        public function getNewSubscription($userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string');
            $this->_query[self::RESPONSE] = self::JSON_FORMAT;
            return $this->_getResponse(sprintf(self::URL_YOUTUBE_NEW_SUBSCRIPTION, $userId), $this->_query);
        }

        public function subscribeToChannel($channel, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = Eden_Template::i()->set(self::CHANNEL, $channel)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
  xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <?php if(!is_null($channel)): ?>
    <category scheme="http://gdata.youtube.com/schemas/2007/subscriptiontypes.cat"
      term="channel"/>
    <yt:username><?php echo $channel; ?></yt:username>
  <?php endif; ?>
  <?php if(!is_null($user)): ?>
    <category scheme="http://gdata.youtube.com/schemas/2007/subscriptiontypes.cat"
      term="user"/>
    <yt:username><?php echo $user; ?></yt:username>
  <?php endif; ?>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_SUBSCRIPTION, $userId), $query);
        }

        public function subscribeToUser($user, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = Eden_Template::i()->set(self::USER, $user)->parsePHP('<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
  xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <?php if(!is_null($channel)): ?>
    <category scheme="http://gdata.youtube.com/schemas/2007/subscriptiontypes.cat"
      term="channel"/>
    <yt:username><?php echo $channel; ?></yt:username>
  <?php endif; ?>
  <?php if(!is_null($user)): ?>
    <category scheme="http://gdata.youtube.com/schemas/2007/subscriptiontypes.cat"
      term="user"/>
    <yt:username><?php echo $user; ?></yt:username>
  <?php endif; ?>
</entry>', true);
            return $this->_post(sprintf(self::URL_YOUTUBE_SUBSCRIPTION, $userId), $query);
        }

        public function unsubscribe($subscriptionId, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            return $this->_delete(sprintf(self::URL_YOUTUBE_UNSUBSCRIPTION, $userId, $subscriptionId));
        }

    }

}
/* Eden_Google_Youtube_Upload */
if (!class_exists('Eden_Google_Youtube_Upload')) {

    class Eden_Google_Youtube_Upload extends Eden_Google_Base {

        const URL_YOUTUBE_UPLOAD = 'http://uploads.gdata.youtube.com/action/GetUploadToken';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $developerId) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_developerId = $developerId;
        }

        public function getUploadToken($title, $description, $category, $keyword, $userId = self::DEFAULT_VALUE) {
            Eden_Google_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            $query = Eden_Template::i()->set(self::TITLE, $title)->set(self::DESCRIPTION, $description)->set(self::CATEGORY, $category)->set(self::KEYWORD, $keyword)->parsePHP('<?xml version="1.0"?>
<entry xmlns="http://www.w3.org/2005/Atom" xmlns:media="http://search.yahoo.com/mrss/" xmlns:yt="http://gdata.youtube.com/schemas/2007">
  <media:group>
    <media:title type="plain"><?php echo $title; ?></media:title>
    <media:description type="plain">
    	<?php echo $description; ?>
    </media:description>
    <media:category scheme="http://gdata.youtube.com/schemas/2007/categories.cat">
		<?php echo $category; ?>
    </media:category>
    <media:keywords><?php $keyword; ?></media:keywords>
  </media:group>
</entry>', true);
            return $this->_upload(sprintf(self::URL_YOUTUBE_UPLOAD, $userId), $query);
        }

        public function upload($uploadToken, $postUrl, $redirectUrl) {
            Eden_Google_Error::i()->argument(1, 'object', 'string')->argument(2, 'object', 'string')->argument(3, 'string');
            $query = Eden_Template::i()->set(self::UPLOAD_TOKEN, $uploadToken)->set(self::REDIRECT_URL, $redirectUrl)->set(self::POST_URL, $postUrl)->parsePHP('<form action="<?php echo $postUrl; ?>?nexturl=<?php echo $redirectUrl; ?>" method="post" enctype="multipart/form-data"> 
        <input name="file" type="file"/>
        <input name="token" type="hidden" value="<?php echo $uploadToken; ?>"/>
        <input value="Upload Video File" type="submit" />
</form>', true);
            return $query;
        }

    }

}
/* Eden_Facebook */
if (!class_exists('Eden_Facebook')) {

    class Eden_Facebook extends \Eden {

        const RSS = 'https://www.facebook.com/feeds/page.php?id=%s&format=rss20';
        const RSS_AGENT = 'Mozilla/5.0 (X11;U;Linux x86_64;en-US;rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick) Firefox/3.6.13';

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function auth($key, $secret, $redirect) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            return Eden_Facebook_Auth::i($key, $secret, $redirect);
        }

        public function event($token, $name, $start, $end) {
            return Eden_Facebook_Event::i($token, $name, $start, $end);
        }

        public function fql($token) {
            Eden_Facebook_Error::i()->argument(1, 'string');
            return Eden_Facebook_Fql::i($token);
        }

        public function graph($token) {
            Eden_Facebook_Error::i()->argument(1, 'string');
            return Eden_Facebook_Graph::i($token);
        }

        public function link($token, $url) {
            return Eden_Facebook_Link::i($token, $url);
        }

        public function post($token, $message) {
            return Eden_Facebook_Post::i($token, $message);
        }

        public function rss($id) {
            Eden_Facebook_Error::i()->argument(1, 'int');
            return Eden_Curl::i()->setUrl(sprintf(self::RSS, $id))->setUserAgent(self::RSS_AGENT)->setConnectTimeout(10)->setFollowLocation(true)->setTimeout(60)->verifyPeer(false)->getSimpleXmlResponse();
        }

        public function subscribe($clientId, $secret) {
            return Eden_Facebook_Subscribe::i($clientId, $secret);
        }

    }

}
/* Eden_Facebook_Error */
if (!class_exists('Eden_Facebook_Error')) {

    class Eden_Facebook_Error extends Eden_Error {

        const AUTHENTICATION_FAILED = 'Application authentication failed.Facebook returned %s: %s';
        const GRAPH_FAILED = 'Call to graph.facebook.com failed.Facebook returned %s: %s';
        const REQUIRES_AUTH = 'Call to %s requires authentication.Please set token first or set argument 4 in setObject() to false.';

    }

}
/* Eden_Facebook_Auth */
if (!class_exists('Eden_Facebook_Auth')) {

    class Eden_Facebook_Auth extends Eden_Oauth2_Client {

        const REQUEST_URL = 'https://www.facebook.com/dialog/oauth';
        const ACCESS_URL = 'https://graph.facebook.com/oauth/access_token';
        const USER_AGENT = 'facebook-php-3.1';

        protected $_key = NULL;
        protected $_secret = NULL;
        protected $_redirect = NULL;

        // public static function i() {
        //     return self::_getMultiple(__CLASS__);
        // }

        public function __construct($key, $secret, $redirect) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            parent::__construct($key, $secret, $redirect, self::REQUEST_URL, self::ACCESS_URL);
        }

    }

}
/* Eden_Facebook_Graph */
if (!class_exists('Eden_Facebook_Graph')) {

    class Eden_Facebook_Graph extends \Eden {

        const GRAPH_URL = 'https://graph.facebook.com/';
        const LOGOUT_URL = 'https://www.facebook.com/logout.php?next=%s&access_token=%s';

        protected $_token = NULL;
        protected $_list = array('Friends', 'Home', 'Feed', 'Likes', 'Movies', 'Music', 'Books', 'Photos', 'Albums', 'Videos', 'VideoUploads', 'Events', 'Groups', 'Checkins');
        protected $_search = array('Posts', 'Users', 'Pages', 'Likes', 'Places', 'Events', 'Groups', 'Checkins');

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __call($name, $args) {
            if (strpos($name, 'get') === 0 && in_array(substr($name, 3), $this->_list)) {
                $key = preg_replace("/([A-Z])/", "/$1", $name);
                $key = strtolower(substr($key, 4));
                $id = 'me';
                if (!empty($args)) {
                    $id = array_shift($args);
                }array_unshift($args, $id, $key);
                return call_user_func_array(array($this, '_getList'), $args);
            } else if (strpos($name, 'search') === 0 && in_array(substr($name, 6), $this->_search)) {
                $key = strtolower(substr($name, 6));
                array_unshift($args, $key);
                return call_user_func_array(array($this, '_search'), $args);
            }
        }

        public function __construct($token) {
            $this->_token = $token;
        }

        public function addAlbum($id, $name, $message) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'int')->argument(2, 'string')->argument(3, 'string');
            $url = self::GRAPH_URL . $id . '/albums';
            $post = array('name' => $name, 'message' => $message);
            $query = array('access_token' => $this->_token);
            $url.='?' . http_build_query($query);
            $results = json_decode($this->_call($url, $post), true);
            return $results['id'];
        }

        public function addComment($id, $message) {
            Eden_Facebook_Error::i()->argument(1, 'int')->argument(2, 'string');
            $url = self::GRAPH_URL . $id . '/comments';
            $post = array('message' => $message);
            $query = array('access_token' => $this->_token);
            $url.='?' . http_build_query($query);
            $results = json_decode($this->_call($url, $post), true);
            return $results['id'];
        }

        public function attendEvent($id) {
            Eden_Facebook_Error::i()->argument(1, 'int');
            $url = self::GRAPH_URL . $id . '/attending';
            $query = array('access_token' => $this->_token);
            $url.='?' . http_build_query($query);
            json_decode($this->_call($url), true);
            return $this;
        }

        public function checkin($id, $message, $latitude, $longitude, $place, $tags) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'int')->argument(2, 'string')->argument(3, 'float')->argument(4, 'float')->argument(5, 'int')->argument(6, 'string', 'array');
            $url = self::GRAPH_URL . $id . '/checkins';
            $post = array('message' => $message);
            $query = array('access_token' => $this->_token);
            $url.='?' . http_build_query($query);
            if ($message) {
                $post['message'] = $message;
            }if ($latitude && $longitute) {
                $post['coordinates'] = json_encode(array('latitude' => $latitude, 'longitude' => $longitude));
            }if ($place) {
                $post['place'] = $place;
            }if ($tags) {
                $post['tags'] = $tags;
            }$results = json_decode($this->_call($url, $post), true);
            return $results['id'];
        }

        public function createNote($id = 'me', $subject, $message) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'int')->argument(2, 'string')->argument(3, 'string');
            $url = self::GRAPH_URL . $id . '/notes';
            $post = array('subject' => $subject, 'message' => $message);
            $query = array('access_token' => $this->_token);
            $url.='?' . http_build_query($query);
            $results = json_decode($this->_call($url, $post), true);
            return $results['id'];
        }

        public function declineEvent($id) {
            Eden_Facebook_Error::i()->argument(1, 'int');
            $url = self::GRAPH_URL . $id . '/declined';
            $query = array('access_token' => $this->_token);
            $url.='?' . http_build_query($query);
            json_decode($this->_call($url), true);
            return $this;
        }

        public function event($name, $start, $end) {
            return Eden_Facebook_Event::i($this->_token, $name, $start, $end);
        }

        public function getFields($id = 'me', $fields) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'int')->argument(2, 'string', 'array');
            if (is_array($fields)) {
                $fields = implode(',', $fields);
            }return $this->getObject($id, NULL, array('fields' => $fields));
        }

        public function getLogoutUrl($redirect) {
            Eden_Facebook_Error::i()->argument(1, 'url');
            return sprintf(self::LOGOUT_URL, urlencode($redirect), $this->_token);
        }

        public function getObject($id = 'me', $connection = NULL, array $query = array(), $auth = true) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'int')->argument(2, 'string', 'null')->argument(3, 'array')->argument(4, 'bool');
            if ($connection) {
                $connection = '/' . $connection;
            }$url = self::GRAPH_URL . $id . $connection;
            if ($auth) {
                $query['access_token'] = $this->_token;
            }if (!empty($query)) {
                $url.='?' . http_build_query($query);
            }$object = $this->_call($url);
            $object = json_decode($object, true);
            if (isset($object['error'])) {
                Eden_Facebook_Error::i()->setMessage(Eden_Facebook_Error::GRAPH_FAILED)->addVariable($url)->addVariable($object['error']['type'])->addVariable($object['error']['message'])->trigger();
            }return $object;
        }

        public function getPermissions($id = 'me') {
            Eden_Facebook_Error::i()->argument(1, 'string', 'int');
            $permissions = $this->getObject($id, 'permissions');
            return $permissions['data'];
        }

        public function getPictureUrl($id = 'me', $token = true) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'int')->argument(2, 'bool');
            $url = self::GRAPH_URL . $id . '/picture';
            if ($token) {
                $url.='?access_token=' . $this->_token;
            }return $url;
        }

        public function getUser() {
            return $this->getObject('me');
        }

        public function like($id) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'int');
            $url = self::GRAPH_URL . $id . '/likes';
            $query = array('access_token' => $this->_token);
            $url.='?' . http_build_query($query);
            $this->_call($url);
            return $this;
        }

        public function link($url) {
            return Eden_Facebook_Link::i($this->_token, $url);
        }

        public function maybeEvent($id) {
            Eden_Facebook_Error::i()->argument(1, 'int');
            $url = self::GRAPH_URL . $id . '/maybe';
            $query = array('access_token' => $this->_token);
            $url.='?' . http_build_query($query);
            json_decode($this->_call($url), true);
            return $this;
        }

        public function post($message) {
            return Eden_Facebook_Post::i($this->_token, $message);
        }

        public function uploadPhoto($albumId, $file, $message = NULL) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'int')->argument(2, 'file')->argument(3, 'string', 'null');
            $url = self::GRAPH_URL . $albumId . '/photos';
            $post = array('source' => '@' . $file);
            $query = array('access_token' => $this->_token);
            if ($message) {
                $post['message'] = $message;
            }$url.='?' . http_build_query($query);
            $results = Eden_Curl::i()->setUrl($url)->setConnectTimeout(10)->setFollowLocation(true)->setTimeout(60)->verifyPeer(false)->setUserAgent(Eden_Facebook_Auth::USER_AGENT)->setHeaders('Expect')->when(!empty($post), 2)->setPost(true)->setPostFields($post)->getJsonResponse();
            return $results['id'];
        }

        protected function _call($url, array $post = array()) {
            return Eden_Curl::i()->setUrl($url)->setConnectTimeout(10)->setFollowLocation(true)->setTimeout(60)->verifyPeer(false)->setUserAgent(Eden_Facebook_Auth::USER_AGENT)->setHeaders('Expect')->when(!empty($post), 2)->setPost(true)->setPostFields(http_build_query($post))->getResponse();
        }

        protected function _getList($id, $connection, $start = 0, $range = 0, $since = 0, $until = 0, $dateFormat = NULL) {
            $query = array();
            if ($start > 0) {
                $query['offset'] = $start;
            }if ($range > 0) {
                $query['limit'] = $range;
            }if (is_string($since)) {
                $since = strtotime($since);
            }if (is_string($until)) {
                $until = strtotime($until);
            }if ($since !== 0) {
                $query['since'] = $since;
            }if ($until !== 0) {
                $query['until'] = $until;
            }$list = $this->getObject($id, $connection, $query);
            return $list['data'];
        }

        protected function _search($connection, $query, $fields = NULL) {
            $query = array('type' => $connection, 'q' => $query);
            if (is_array($fields)) {
                $fields = implode(',', $fields);
            }if ($fields) {
                $query['fields'] = $fields;
            }$results = $this->getObject('search', NULL, $query);
            return $results['data'];
        }

    }

}
/* Eden_Facebook_Post */
if (!class_exists('Eden_Facebook_Post')) {

    class Eden_Facebook_Post extends \Eden {

        protected $_id = 'me';
        protected $_post = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token, $message) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_token = $token;
            $this->_post['message'] = $message;
        }

        public function create() {
            $url = Eden_Facebook_Graph::GRAPH_URL . $this->_id . '/feed';
            $query = array('access_token' => $this->_token);
            $url.='?' . http_build_query($query);
            $response = Eden_Curl::i()->setUrl($url)->setConnectTimeout(10)->setFollowLocation(true)->setTimeout(60)->verifyPeer(false)->setUserAgent(Eden_Facebook_Auth::USER_AGENT)->setHeaders('Expect')->setPost(true)->setPostFields(http_build_query($this->_post))->getJsonResponse();
            return $response;
        }

        public function setDescription($description) {
            Eden_Facebook_Error::i()->argument(1, 'string');
            $this->_post['description'] = $description;
            return $this;
        }

        public function setIcon($url) {
            Eden_Facebook_Error::i()->argument(1, 'url');
            $this->_post['icon'] = $url;
            return $this;
        }

        public function setId($id) {
            Eden_Facebook_Error::i()->argument(1, 'numeric');
            $this->_id = $id;
            return $this;
        }

        public function setLink($url) {
            Eden_Facebook_Error::i()->argument(1, 'url');
            $this->_post['link'] = $url;
            return $this;
        }

        public function setPicture($url) {
            Eden_Facebook_Error::i()->argument(1, 'url');
            $this->_post['picture'] = $url;
            return $this;
        }

        public function setTitle($title) {
            Eden_Facebook_Error::i()->argument(1, 'string');
            $this->_post['name'] = $title;
            return $this;
        }

        public function setVideo($url) {
            Eden_Facebook_Error::i()->argument(1, 'url');
            $this->_post['video'] = $url;
            return $this;
        }

    }

}
/* Eden_Facebook_Select */
if (!class_exists('Eden_Facebook_Select')) {

    class Eden_Facebook_Select extends \Eden {

        protected $_select = NULL;
        protected $_from = NULL;
        protected $_where = array();
        protected $_sortBy = array();
        protected $_page = NULL;
        protected $_length = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __toString() {
            return $this->getQuery();
        }

        public function from($from) {
            Eden_Facebook_Error::i()->argument(1, 'string');
            $this->_from = $from;
            return $this;
        }

        public function limit($page, $length) {
            Eden_Facebook_Error::i()->argument(1, 'numeric')->argument(2, 'numeric');
            $this->_page = $page;
            $this->_length = $length;
            return $this;
        }

        public function getQuery() {
            $where = empty($this->_where) ? '' : 'WHERE ' . implode(' AND ', $this->_where);
            $sort = empty($this->_sortBy) ? '' : 'ORDER BY ' . implode(',', $this->_sortBy);
            $limit = is_null($this->_page) ? '' : 'LIMIT ' . $this->_page . ',' . $this->_length;
            if (empty($this->_select) || $this->_select == '*') {
                $this->_select = implode(',', self::$_columns[$this->_from]);
            }$query = sprintf('SELECT %s FROM %s %s %s %s;', $this->_select, $this->_from, $where, $sort, $limit);
            return str_replace(' ', ' ', $query);
        }

        public function select($select = '*') {
            Eden_Facebook_Error::i()->argument(1, 'string', 'array');
            if (is_array($select)) {
                $select = implode(',', $select);
            }$this->_select = $select;
            return $this;
        }

        public function sortBy($field, $order = 'ASC') {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_sortBy[] = $field . ' ' . $order;
            return $this;
        }

        public function where($where) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'array');
            if (is_string($where)) {
                $where = array($where);
            }$this->_where = array_merge($this->_where, $where);
            return $this;
        }

        protected static $_columns = array('album' => array('aid', 'object_id', 'owner', 'cover_pid', 'cover_object_id', 'name', 'created', 'modified', 'description', 'location', 'size', 'link', 'visible', 'modified_major', 'edit_link', 'type', 'can_upload', 'photo_count', 'video_count'), 'application' => array('app_id', 'api_key', 'canvas_name', 'display_name', 'icon_url', 'logo_url', 'company_name', 'developers', 'description', 'daily_active_users', 'weekly_active_users', 'monthly_active_users', 'category', 'subcategory', 'is_facebook_app', 'restriction_info', 'app_domains', 'auth_dialog_data_help_url', 'auth_dialog_description', 'auth_dialog_headline', 'auth_dialog_perms_explanation', 'auth_referral_user_perms', 'auth_referral_friend_perms', 'auth_referral_default_activity_privacy', 'auth_referral_enabled', 'auth_referral_extended_perms', 'auth_referral_response_type', 'canvas_fluid_height', 'canvas_fluid_width', 'canvas_url', 'contact_email', 'created_time', 'creator_uid', 'deauth_callback_url', 'iphone_app_store_id', 'hosting_url', 'mobile_web_url', 'page_tab_default_name', 'page_tab_url', 'privacy_policy_url', 'secure_canvas_url', 'secure_page_tab_url', 'server_ip_whitelist', 'social_discovery', 'terms_of_service_url', 'update_ip_whitelist', 'user_support_email', 'user_support_url', 'website_url'), 'apprequest' => array('request_id', 'app_id', 'recipient_uid', 'sender_uid', 'message', 'data', 'created_time'), 'checkin' => array('checkin_id', 'author_uid', 'page_id', 'app_id', 'post_id', 'coords', 'timestamp', 'tagged_uids', 'message'), 'comment' => array('xid', 'object_id', 'post_id', 'fromid', 'time', 'text', 'id', 'username ', 'reply_xid', 'post_fbid', 'app_id', 'likes', 'comments', 'user_likes', 'is_private'), 'comments_info' => array('app_id', 'xid', 'count', 'updated_time'), 'connection' => array('source_id', 'target_id', 'target_type', 'is_following'), 'cookies' => array('uid', 'name', 'value', 'expires', 'path'), 'developer' => array('developer_id', 'application_id', 'role'), 'domain' => array('domain_id', 'domain_name'), 'domain_admin' => array('owner_id', 'domain_id'), 'event' => array('eid', 'name', 'tagline', 'nid', 'pic_small', 'pic_big', 'pic_square', 'pic', 'host', 'description', 'event_type', 'event_subtype', 'start_time', 'end_time', 'creator', 'update_time', 'location', 'venue', 'privacy', 'hide_guest_list', 'can_invite_friends'), 'event_member' => array('uid', 'eid', 'rsvp_status', 'start_time'), 'family' => array('profile_id', 'uid', 'name', 'birthday', 'relationship'), 'friend' => array('uid1', 'uid2'), 'friend_request' => array('uid_to', 'uid_from', 'time', 'message', 'unread'), 'friendlist' => array('owner', 'flid', 'name'), 'friendlist_member' => array('flid', 'uid'), 'group' => array('gid', 'name', 'nid', 'pic_small', 'pic_big', 'pic', 'description', 'group_type', 'group_subtype', 'recent_news', 'creator', 'update_time', 'office', 'website', 'venue', 'privacy', 'icon', 'icon34', 'icon68', 'email', 'version'), 'group_member' => array('uid', 'gid', 'administrator', 'positions', 'unread', 'bookmark_order'), 'insights' => array('object_id', 'metric', 'end_time', 'period', 'value'), 'like' => array('object_id', 'post_id', 'user_id', 'object_type'), 'link' => array('link_id', 'owner', 'owner_comment', 'created_time', 'title', 'summary', 'url', 'picture', 'image_urls'), 'link_stat' => array('url', 'normalized_url', 'share_count', 'like_count', 'comment_count', 'total_count', 'click_count', 'comments_fbid', 'commentsbox_count'), 'mailbox_folder' => array('folder_id', 'viewer_id', 'name', 'unread_count', 'total_count'), 'message' => array('message_id', 'thread_id', 'author_id', 'body', 'created_time', 'attachment', 'viewer_id'), 'note' => array('uid', 'note_id', 'created_time', 'updated_time', 'content', 'content_html', 'title'), 'notification' => array('notification_id', 'sender_id', 'recipient_id', 'created_time', 'updated_time', 'title_html', 'title_text', 'body_html', 'body_text', 'href', 'app_id', 'is_unread', 'is_hidden', 'object_id', 'object_type', 'icon_url'), 'object_url' => array('url', 'id', 'type', 'site'), 'page' => array('page_id', 'name', 'username', 'description', 'categories', 'is_community_page', 'pic_small', 'pic_big', 'pic_square', 'pic', 'pic_large', 'page_url', 'fan_count', 'type', 'website', 'has_added_app', 'general_info', 'can_post', 'checkins', 'founded', 'company_overview', 'mission', 'products', 'location', 'parking', 'hours', 'pharma_safety_info', 'public_transit', 'attire', 'payment_options', 'culinary_team', 'general_manager', 'price_range', 'restaurant_services', 'restaurant_specialties', 'phone', 'release_date', 'genre', 'starring', 'screenplay_by', 'directed_by', 'produced_by', 'studio', 'awards', 'plot_outline', 'season', 'network', 'schedule', 'written_by', 'band_members', 'hometown', 'current_location', 'record_label', 'booking_agent', 'press_contact', 'artists_we_like', 'influences', 'band_interests', 'bio', 'affiliation', 'birthday', 'personal_info', 'personal_interests', 'built', 'features', 'mpg'), 'page_admin' => array('uid', 'page_id', 'type'), 'page_blocked_user' => array('page_id', 'uid'), 'page_fan' => array('uid', 'page_id', 'type', 'profile_section', 'created_time'), 'permissions' => array('uid', 'PERMISSION_NAME'), 'permissions_info' => array('permission_name', 'header', 'summary'), 'photo' => array('pid', 'aid', 'owner', 'src_small', 'src_small_width', 'src_small_height', 'src_big', 'src_big_width', 'src_big_height', 'src', 'src_width', 'src_height', 'link', 'caption', 'created', 'modified', 'position', 'object_id', 'album_object_id', 'images'), 'photo_tag' => array('pid', 'subject', 'object_id', 'text', 'xcoord', 'ycoord', 'created'), 'place' => array('page_id', 'name', 'description', 'geometry', 'latitude', 'longitude', 'checkin_count', 'display_subtext'), 'privacy' => array('id', 'object_id', 'value ', 'description', 'allow', 'deny', 'owner_id', 'networks', 'friends'), 'privacy_setting' => array('name', 'value ', 'description', 'allow', 'deny', 'networks', 'friends'), 'profile' => array('id', 'can_post', 'name', 'url', 'pic', 'pic_square', 'pic_small', 'pic_big', 'pic_crop', 'type', 'username'), 'question' => array('id', 'owner', 'question', 'created_time', 'updated_time'), 'question_option' => array('id', 'question_id', 'name', 'votes', 'object_id', 'owner', 'created_time'), 'question_option_votes' => array('option_id', 'voter_id'), 'review' => array('reviewee_id', 'reviewer_id', 'review_id', 'message', 'created_time', 'rating'), 'standard_friend_info' => array('uid1', 'uid2'), 'standard_user_info' => array('uid', 'name', 'username', 'third_party_id', 'first_name', 'last_name', 'locale', 'affiliations', 'profile_url', 'timezone', 'birthday', 'sex', 'proxied_email', 'current_location', 'allowed_restrictions'), 'status' => array('uid', 'status_id', 'time', 'source', 'message'), 'stream' => array('post_id', 'viewer_id ', 'app_id', 'source_id ', 'updated_time', 'created_time', 'filter_key', 'attribution ', 'actor_id', 'target_id', 'message', 'app_data', 'action_links', 'attachment', 'impressions', 'comments', 'likes', 'privacy', 'permalink', 'xid', 'tagged_ids', 'message_tags', 'description', 'description_tags'), 'stream_filter' => array('uid', 'filter_key ', 'name', 'rank ', 'icon_url', 'is_visible', 'type', 'value'), 'stream_tag' => array('post_id', 'actor_id', 'target_id'), 'thread' => array('thread_id', 'folder_id', 'subject', 'recipients', 'updated_time', 'parent_message_id', 'parent_thread_id', 'message_count', 'snippet', 'snippet_author', 'object_id', 'unread', 'viewer_id'), 'translation' => array('locale', 'native_hash', 'native_string', 'description', 'translation', 'approval_status', 'pre_hash_string', 'best_string'), 'unified_message' => array('message_id', 'thread_id', 'subject', 'body', 'unread', 'action_id', 'timestamp', 'tags', 'sender', 'recipients', 'object_sender', 'html_body', 'attachments', 'attachment_map', 'shares', 'share_map'), 'unified_thread' => array('action_id', 'archived', 'can_reply', 'folder', 'former_participants', 'has_attachments', 'is_subscribed', 'last_visible_add_action_id', 'name', 'num_messages', 'num_unread', 'object_participants', 'participants', 'senders', 'single_recipient', 'snippet', 'snippet_sender', 'snippet_message_has_attachment', 'subject', 'tags', 'thread_id', 'thread_participants', 'timestamp', 'unread'), 'unified_thread_action' => array('action_id', 'actor', 'thread_id', 'timestamp', 'type', 'users'), 'unified_thread_count' => array('folder', 'unread_count', 'unseen_count', 'last_action_id', 'last_seen_time', 'total_threads'), 'url_like' => array('user_id', 'url'), 'user' => array('uid', 'username', 'first_name', 'middle_name', 'last_name', 'name', 'pic_small', 'pic_big', 'pic_square', 'pic', 'affiliations', 'profile_update_time', 'timezone', 'religion', 'birthday', 'birthday_date', 'sex', 'hometown_location', 'meeting_sex', 'meeting_for', 'relationship_status', 'significant_other_id', 'political', 'current_location', 'activities', 'interests', 'is_app_user', 'music', 'tv', 'movies', 'books', 'quotes', 'about_me', 'hs_info', 'education_history', 'work_history', 'notes_count', 'wall_count', 'status', 'has_added_app', 'online_presence', 'locale', 'proxied_email', 'profile_url', 'email_hashes', 'pic_small_with_logo', 'pic_big_with_logo', 'pic_square_with_logo', 'pic_with_logo', 'allowed_restrictions', 'verified', 'profile_blurb', 'family', 'website', 'is_blocked', 'contact_email', 'email', 'third_party_id', 'name_format', 'video_upload_limits', 'games', 'is_minor', 'work', 'education', 'sports', 'favorite_athletes', 'favorite_teams', 'inspirational_people', 'languages', 'likes_count', 'friend_count', 'mutual_friend_count', 'can_post'), 'video' => array('vid', 'owner', 'album_id', 'title', 'description', 'link', 'thumbnail_link', 'embed_html', 'updated_time', 'created_time', 'length', 'src', 'src_hq'), 'video_tag' => array('vid', 'subject', 'updated_time', 'created_time'));

    }

}
/* Eden_Facebook_Search */
if (!class_exists('Eden_Facebook_Search')) {

    class Eden_Facebook_Search extends \Eden {

        const ASC = 'ASC';
        const DESC = 'DESC';

        protected $_database = NULL;
        protected $_table = NULL;
        protected $_columns = array();
        protected $_filter = array();
        protected $_sort = array();
        protected $_start = 0;
        protected $_range = 0;
        protected $_group = array();

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __call($name, $args) {
            if (strpos($name, 'filterBy') === 0) {
                $separator = '_';
                if (isset($args[1]) && is_scalar($args[1])) {
                    $separator = (string) $args[1];
                }$key = Eden_Type_String::i($name)->substr(8)->preg_replace("/([A-Z])/", $separator . "$1")->substr(strlen($separator))->strtolower()->get();
                if (!isset($args[0])) {
                    $args[0] = NULL;
                }$key = $key . '=%s';
                $this->addFilter($key, $args[0]);
                return $this;
            }if (strpos($name, 'sortBy') === 0) {
                $separator = '_';
                if (isset($args[1]) && is_scalar($args[1])) {
                    $separator = (string) $args[1];
                }$key = Eden_Type_String::i($name)->substr(6)->preg_replace("/([A-Z])/", $separator . "$1")->substr(strlen($separator))->strtolower()->get();
                if (!isset($args[0])) {
                    $args[0] = self::ASC;
                }$this->addSort($key, $args[0]);
                return $this;
            }try {
                return parent::__call($name, $args);
            } catch (Eden_Error $e) {
                Eden_Facebook_Error::i($e->getMessage())->trigger();
            }
        }

        public function __construct(Eden_Facebook_Fql $database) {
            $this->_database = $database;
        }

        public function addFilter() {
            Eden_Facebook_Error::i()->argument(1, 'string');
            $this->_filter[] = func_get_args();
            return $this;
        }

        public function addSort($column, $order = self::ASC) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string');
            if ($order != self::DESC) {
                $order = self::ASC;
            }$this->_sort[$column] = $order;
            return $this;
        }

        public function getCollection($key = 'last') {
            $rows = $this->getRows($key);
            if (count($this->_group) == 1) {
                return Eden_Collection::i($rows);
            }foreach ($rows as $key => $collection) {
                $rows[$key] = Eden_Collection::i($collection['fql_result_set']);
            }return $rows;
        }

        public function getRows($key = 'last') {
            $this->group($key);
            if (empty($this->_group)) {
                return array();
            }$group = array();
            foreach ($this->_group as $key => $query) {
                $this->_table = $query['table'];
                $this->_columns = $query['columns'];
                $this->_filter = $query['filter'];
                $this->_sort = $query['sort'];
                $this->_start = $query['start'];
                $this->_range = $query['range'];
                $query = $this->_getQuery();
                if (!empty($this->_columns)) {
                    $query->select(implode(',', $this->_columns));
                }foreach ($this->_sort as $name => $value) {
                    $query->sortBy($name, $value);
                }if ($this->_range) {
                    $query->limit($this->_start, $this->_range);
                }$group[$key] = $query;
            }$query = $group;
            if (count($query) == 1) {
                $query = $group[$key];
            }$results = $this->_database->query($query);
            return $results;
        }

        public function getTotal() {
            $query = $this->_getQuery()->select('COUNT(*) as total');
            $rows = $this->_database->query($query);
            if (!isset($rows[0]['total'])) {
                return 0;
            }return $rows[0]['total'];
        }

        public function group($key) {
            Eden_Facebook_Error::i()->argument(1, 'scalar');
            if (is_null($this->_table)) {
                return $this;
            }$this->_group[$key] = array('table' => $this->_table, 'columns' => $this->_columns, 'filter' => $this->_filter, 'sort' => $this->_sort, 'start' => $this->_start, 'range' => $this->_range);
            $this->_table = NULL;
            $this->_columns = array();
            $this->_filter = array();
            $this->_sort = array();
            $this->_start = 0;
            $this->_range = 0;
            return $this;
        }

        public function setColumns($columns) {
            if (!is_array($columns)) {
                $columns = func_get_args();
            }$this->_columns = $columns;
            return $this;
        }

        public function setPage($page) {
            Eden_Facebook_Error::i()->argument(1, 'int');
            if ($page < 1) {
                $page = 1;
            }$this->_start = ($page - 1) * $this->_range;
            return $this;
        }

        public function setRange($range) {
            Eden_Facebook_Error::i()->argument(1, 'int');
            if ($range < 0) {
                $range = 25;
            }$this->_range = $range;
            return $this;
        }

        public function setStart($start) {
            Eden_Facebook_Error::i()->argument(1, 'int');
            if ($start < 0) {
                $start = 0;
            }$this->_start = $start;
            return $this;
        }

        public function setTable($table) {
            Eden_Facebook_Error::i()->argument(1, 'string');
            $this->_table = $table;
            return $this;
        }

        protected function _getQuery() {
            $query = $this->_database->select()->from($this->_table);
            foreach ($this->_filter as $i => $filter) {
                $where = array_shift($filter);
                if (!empty($filter)) {
                    foreach ($filter as $i => $value) {
                        if (!is_string($value)) {
                            continue;
                        }$filter[$i] = "'" . $value . "'";
                    }$where = vsprintf($where, $filter);
                }$query->where($where);
            }return $query;
        }

    }

}
/* Eden_Facebook_Subscribe */
if (!class_exists('Eden_Facebook_Subscribe')) {

    class Eden_Facebook_Subscribe extends \Eden {

        const SUBSCRIBE_URL = 'https://graph.facebook.com/%s/subscriptions';
        const APPLICATION_URL = 'https://graph.facebook.com/oauth/access_token?client_id=%s&client_secret=%s&grant_type=%s';
        const CREDENTIALS = 'client_credentials';

        protected $_token = NULL;
        protected $_meta = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($clientId, $secret) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_appId = $clientId;
            $tokenUrl = sprintf(self::APPLICATION_URL, $clientId, $secret, self::CREDENTIALS);
            $appToken = file_get_contents($tokenUrl);
            parse_str($appToken, $token);
            if (!isset($token['access_token'])) {
                return $token;
            } else {
                $this->_token = $token['access_token'];
            }
        }

        public function getMeta() {
            return $this->_meta;
        }

        public function getSubscription() {
            return $this->_getResponse(sprintf(self::SUBSCRIBE_URL, $this->_appId));
        }

        public function subscribe($object, $fields, $callbackUrl) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'url');
            $query = array('object' => $object, 'fields' => $fields, 'callback_url' => $callbackUrl, 'verify_token' => sha1($this->_appId . $object . $callbackUrl));
            $token = array('access_token' => $this->_token);
            $url = sprintf(self::SUBSCRIBE_URL, $this->_appId) . '?' . http_build_query($token);
            return $this->_post($url, $query);
        }

        protected function _post($url, array $query = array()) {
            $curl = Eden_Curl::i()->setConnectTimeout(10)->setFollowLocation(true)->setTimeout(60)->verifyHost(false)->verifyPeer(false)->setUrl($url)->setPost(true)->setPostFields($query)->setHeaders('Expect');
            $response = $curl->getJsonResponse();
            $this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['query'] = $query;
            $this->_meta['response'] = $response;
            return $response;
        }

        protected function _getResponse($url, array $query = array()) {
            $query['access_token'] = $this->_token;
            $url = $url . '?' . http_build_query($query);
            $curl = Eden_Curl::i()->setUrl($url)->verifyHost(false)->verifyPeer(false)->setTimeout(60);
            $response = $curl->getJsonResponse();
            $this->_meta['url'] = $url;
            $this->_meta['query'] = $query;
            $this->_meta['curl'] = $curl->getMeta();
            $this->_meta['response'] = $response;
            return $response;
        }

    }

}
/* Eden_Facebook_Fql */
if (!class_exists('Eden_Facebook_Fql')) {

    class Eden_Facebook_Fql extends \Eden {

        const SELECT = 'Eden_Facebook_Select';
        const FQL_URL = 'https://graph.facebook.com/fql';

        protected $_queries = array();
        protected $_token = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($token) {
            $this->_token = $token;
        }

        public function getCollection($table, $filters = NULL, array $sort = array(), $start = 0, $range = 0, $index = NULL) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string', 'array', 'null')->argument(4, 'numeric')->argument(5, 'numeric')->argument(6, 'numeric', 'null');
            $results = $this->getRows($table, $filters, $sort, $start, $range, $index);
            $collection = Eden_Collection::i();
            if (is_null($results)) {
                return $collection;
            }if (!is_null($index)) {
                return $this->model($results);
            }return $collection->set($results);
        }

        public function getModel($table, $name, $value) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string', 'numeric');
            $result = $this->getRow($table, $name, $value);
            $model = Eden_Model::i();
            if (is_null($result)) {
                return $model;
            }return $model->set($result);
        }

        public function getRow($table, $name, $value) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string', 'numeric');
            $query = $this->select()->from($table)->where($name . '=' . $value)->limit(0, 1);
            $results = $this->query($query);
            return isset($results[0]) ? $results[0] : NULL;
        }

        public function getRows($table, $filters = NULL, array $sort = array(), $start = 0, $range = 0, $index = NULL) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string', 'array', 'null')->argument(4, 'numeric')->argument(5, 'numeric')->argument(6, 'numeric', 'null');
            $query = $this->select()->from($table);
            if (is_array($filters)) {
                foreach ($filters as $i => $filter) {
                    if (!is_array($filter)) {
                        continue;
                    }$format = array_shift($filter);
                    $filters[$i] = vsprintf($format, $filter);
                }
            }if (!is_null($filters)) {
                $query->where($filters);
            }if (!empty($sort)) {
                foreach ($sort as $key => $value) {
                    if (is_string($key) && trim($key)) {
                        $query->sortBy($key, $value);
                    }
                }
            }if ($range) {
                $query->limit($start, $range);
            }$results = $this->query($query);
            if (!is_null($index)) {
                if (empty($results)) {
                    $results = NULL;
                } else {
                    if ($index == self::FIRST) {
                        $index = 0;
                    }if ($index == self::LAST) {
                        $index = count($results) - 1;
                    }if (isset($results[$index])) {
                        $results = $results[$index];
                    } else {
                        $results = NULL;
                    }
                }
            }return $results;
        }

        public function getRowsCount($table, $filters = NULL) {
            Eden_Facebook_Error::i()->argument(1, 'string')->argument(2, 'string', 'array', 'null');
            $query = $this->select('COUNT(*) as count')->from($table);
            if (is_array($filters)) {
                foreach ($filters as $i => $filter) {
                    if (!is_array($filter)) {
                        continue;
                    }$format = array_shift($filter);
                    $filters[$i] = vsprintf($format, $filter);
                }
            }if (!is_null($filters)) {
                $query->where($filters);
            }$results = $this->query($query);
            if (isset($results[0]['count'])) {
                return $results[0]['count'];
            }return false;
        }

        public function getQueries($index = NULL) {
            if (is_null($index)) {
                return $this->_queries;
            }if ($index == self::FIRST) {
                $index = 0;
            }if ($index == self::LAST) {
                $index = count($this->_queries) - 1;
            }if (isset($this->_queries[$index])) {
                return $this->_queries[$index];
            }return NULL;
        }

        public function query($query) {
            Eden_Facebook_Error::i()->argument(1, 'string', 'array', self::SELECT);
            if (!is_array($query)) {
                $query = array('q' => (string) $query);
            } else {
                foreach ($query as $key => $select) {
                    $query[$key] = (string) $select;
                }$query = array('q' => json_encode($query));
            }$query['access_token'] = $this->_token;
            $url = self::FQL_URL . '?' . http_build_query($query);
            $results = Eden_Curl::i()->setUrl($url)->setConnectTimeout(10)->setFollowLocation(true)->setTimeout(60)->verifyPeer(false)->setUserAgent(Eden_Facebook_Auth::USER_AGENT)->setHeaders('Expect')->getJsonResponse();
            $this->_queries[] = array('query' => $query['q'], 'results' => $results);
            if (isset($results['error']['message'])) {
                Eden_Facebook_Error::i($query['q'] . $results['error']['message'])->trigger();
            }return $results['data'];
        }

        public function search() {
            return Eden_Facebook_Search::i($this);
        }

        public function select($select = '*') {
            Eden_Facebook_Error::i()->argument(1, 'string', 'array');
            return Eden_Facebook_Select::i($select);
        }

    }

}
/* Eden_Twitter */
if (!class_exists('Eden_Twitter')) {

    class Eden_Twitter extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function auth($key, $secret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string');
            return Eden_Twitter_Oauth::i($key, $secret);
        }

        public function directMessage($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Directmessage::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function favorites($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Favorites::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function friends($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Friends::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function geo($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Geo::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function help($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Help::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function lists($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_List::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function saved($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Saved::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function search($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Search::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function spam($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Spam::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function streaming($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Streaming::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function suggestions($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Suggestions::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function timeline($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Timeline::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function trends($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Trends::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function tweets($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Tweets::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

        public function users($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            return Eden_Twitter_Users::i($consumerKey, $consumerSecret, $accessToken, $accessSecret);
        }

    }

}
/* Eden_Twitter_Error */
if (!class_exists('Eden_Twitter_Error')) {

    class Eden_Twitter_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Twitter_Base */
if (!class_exists('Eden_Twitter_Base')) {

    class Eden_Twitter_Base extends Eden_Oauth_Base {

        protected $_consumerKey = NULL;
        protected $_consumerSecret = NULL;
        protected $_accessToken = NULL;
        protected $_accessSecret = NULL;
        protected $_signingKey = NULL;
        protected $_baseString = NULL;
        protected $_signingParams = NULL;
        protected $_url = NULL;
        protected $_authParams = NULL;
        protected $_authHeader = NULL;
        protected $_headers = NULL;
        protected $_query = array();

        public function __construct($consumerKey, $consumerSecret, $accessToken, $accessSecret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string');
            $this->_consumerKey = $consumerKey;
            $this->_consumerSecret = $consumerSecret;
            $this->_accessToken = $accessToken;
            $this->_accessSecret = $accessSecret;
        }

        public function getMeta($key = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'null');
            if (isset($this->_meta[$key])) {
                return $this->_meta[$key];
            }return $this->_meta;
        }

        public function isJson($string) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            json_decode($string);
            return (json_last_error() == JSON_ERROR_NONE);
        }

        protected function _accessKey($array) {
            foreach ($array as $key => $val) {
                if (is_array($val)) {
                    $array[$key] = $this->_accessKey($val);
                }if (is_null($val) || empty($val)) {
                    unset($array[$key]);
                } else if ($val === false) {
                    $array[$key] = 0;
                } else if ($val === true) {
                    $array[$key] = 1;
                }
            }return $array;
        }

        protected function _getResponse($url, array $query = array()) {
            $query = $this->_accessKey($query);
            $rest = Eden_Oauth::i()->consumer($url, $this->_consumerKey, $this->_consumerSecret)->setMethodToGet()->setToken($this->_accessToken, $this->_accessSecret)->setSignatureToHmacSha1();
            $response = $rest->getResponse($query);
            unset($this->_query);
            $this->_meta = $rest->getMeta();
            if ($this->isJson($response)) {
                return json_decode($response, true);
            } else {
                return $response;
            }
        }

        protected function _post($url, array $query = array()) {
            $query = $this->_accessKey($query);
            $rest = Eden_Oauth::i()->consumer($url, $this->_consumerKey, $this->_consumerSecret)->setMethodToPost()->setToken($this->_accessToken, $this->_accessSecret)->setSignatureToHmacSha1();
            $signature = $rest->getSignature($query);
            $authorization = $rest->getAuthorization($signature, false);
            $authorization = $this->_buildQuery($authorization);
            if (is_array($query)) {
                $query = $this->_buildQuery($query);
            }$headers = array();
            $headers[] = Eden_Oauth_Consumer::POST_HEADER;
            $connector = NULL;
            if (strpos($url, '?') === false) {
                $connector = '?';
            } else if (substr($url, -1) != '?') {
                $connector = '&';
            }$url.=$connector . $authorization;
            $curl = Eden_Curl::i()->verifyHost(false)->verifyPeer(false)->setUrl($url)->setPost(true)->setPostFields($query)->setHeaders($headers);
            $response = $curl->getJsonResponse();
            unset($this->_query);
            $this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['authorization'] = $authorization;
            $this->_meta['headers'] = $headers;
            $this->_meta['query'] = $query;
            return $response;
        }

        protected function _upload($url, array $query = array()) {
            $query = $this->_accessKey($query);
            $this->_url = $url;
            $this->_getAuthentication();
            $this->_headers['Expect'] = '';
            foreach ($this->_headers as $k => $v) {
                $headers[] = trim($k . ': ' . $v);
            }$curl = Eden_Curl::i()->verifyHost(false)->verifyPeer(false)->setUrl($url)->setPost(true)->setPostFields($query)->setHeaders($headers);
            $response = $curl->getJsonResponse();
            unset($this->_query);
            $this->_meta = $curl->getMeta();
            $this->_meta['url'] = $url;
            $this->_meta['headers'] = $headers;
            $this->_meta['query'] = $query;
            return $response;
        }

        protected function _getAuthentication() {
            $defaults = array('oauth_version' => '1.0', 'oauth_nonce' => md5(uniqid(rand(), true)), 'oauth_timestamp' => time(), 'oauth_consumer_key' => $this->_consumerKey, 'oauth_signature_method' => 'HMAC-SHA1', 'oauth_token' => $this->_accessToken);
            foreach ($defaults as $k => $v) {
                $this->_signingParams[$this->safeEncode($k)] = $this->safeEncode($v);
            }uksort($this->_signingParams, 'strcmp');
            foreach ($this->_signingParams as $k => $v) {
                $k = $this->safeEncode($k);
                $v = $this->safeEncode($v);
                $_signing_params[$k] = $v;
                $kv[] = "{$k}={$v}";
            }$this->_signingParams = implode('&', $kv);
            $this->_authParams = array_intersect_key($defaults, $_signing_params);
            $base = array('POST', $this->_url, $this->_signingParams);
            $this->_baseString = implode('&', $this->safeEncode($base));
            $this->_signingKey = $this->safeEncode($this->_consumerSecret) . '&' . $this->safeEncode($this->_accessSecret);
            $this->_authParams['oauth_signature'] = $this->safeEncode(base64_encode(hash_hmac('sha1', $this->_baseString, $this->_signingKey, true)));
            foreach ($this->_authParams as $k => $v) {
                $kv[] = "{$k}=\"{$v}\"";
            }$this->_authHeader = 'OAuth ' . implode(',', $kv);
            $this->_headers['Authorization'] = $this->_authHeader;
        }

        protected function safeEncode($data) {
            if (is_array($data)) {
                return array_map(array($this, 'safeEncode'), $data);
            } else if (is_scalar($data)) {
                return str_ireplace(array('+', '%7E'), array(' ', '~'), rawurlencode($data));
            } else {
                return '';
            }
        }

    }

}
/* Eden_Twitter_Oauth */
if (!class_exists('Eden_Twitter_Oauth')) {

    class Eden_Twitter_Oauth extends \Eden {

        const REQUEST_URL = 'https://api.twitter.com/oauth/request_token';
        const AUTHORIZE_URL = 'https://api.twitter.com/oauth/authorize';
        const ACCESS_URL = 'https://api.twitter.com/oauth/access_token';

        protected $_key = NULL;
        protected $_secret = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($key, $secret) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_key = $key;
            $this->_secret = $secret;
        }

        public function getAccessToken($token, $secret, $verifier) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string');
            return Eden_Oauth::i()->consumer(self::ACCESS_URL, $this->_key, $this->_secret)->useAuthorization()->setMethodToPost()->setToken($token, $secret)->setVerifier($verifier)->setSignatureToHmacSha1()->getQueryResponse();
        }

        public function getLoginUrl($token, $redirect, $force_login = false) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'bool');
            $query = array('oauth_token' => $token, 'oauth_callback' => $redirect, 'force_login' => (int) $force_login);
            $query = http_build_query($query);
            return self::AUTHORIZE_URL . '?' . $query;
        }

        public function getRequestToken() {
            return Eden_Oauth::i()->consumer(self::REQUEST_URL, $this->_key, $this->_secret)->useAuthorization()->setMethodToPost()->setSignatureToHmacSha1()->getQueryResponse();
        }

    }

}
/* Eden_Twitter_Directmessage */
if (!class_exists('Eden_Twitter_Directmessage')) {

    class Eden_Twitter_Directmessage extends Eden_Twitter_Base {

        const URL_DIRECT_MESSAGE = 'https://api.twitter.com/1.1/direct_messages.json';
        const URL_SENT_MESSAGE = 'https://api.twitter.com/1.1/direct_messages/sent.json';
        const URL_SHOW_MESSAGE = 'https://api.twitter.com/1.1/direct_messages/show.json';
        const URL_REMOVE_MESSAGE = 'https://api.twitter.com/1.1/direct_messages/destroy.json';
        const URL_NEW_MESSAGE = 'https://api.twitter.com/1.1/direct_messages/new.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getList() {
            return $this->_getResponse(self::URL_DIRECT_MESSAGE, $this->_query);
        }

        public function getSent() {
            return $this->_getResponse(self::URL_SENT_MESSAGE, $this->_query);
        }

        public function getDetail($messageId) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['id'] = $messageId;
            return $this->_getResponse(self::URL_SHOW_MESSAGE, $this->_query);
        }

        public function remove($id) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['id'] = $id;
            return $this->_post(self::URL_REMOVE_MESSAGE, $this->_query);
        }

        public function send($id, $text) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int')->argument(2, 'string');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['screen_name'] = $id;
            }$this->_query['text'] = $text;
            return $this->_post(self::URL_NEW_MESSAGE, $this->_query);
        }

        public function includeEntities() {
            $this->_query['include_entities'] = true;
            return $this;
        }

        public function setCount($count) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['count'] = $count;
            return $this;
        }

        public function setMaxId($maxId) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['max_id'] = $maxId;
            return $this;
        }

        public function setPage($page) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['page'] = $page;
            return $this;
        }

        public function setSinceId($sinceId) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['since_id'] = $sinceId;
            return $this;
        }

        public function setWrap($wrap) {
            Eden_Twitter_Error::i()->argument(1, 'bool');
            $this->_wrap = $wrap;
            return $this;
        }

        public function skipStatus() {
            $this->_query['skip_status'] = true;
            return $this;
        }

    }

}
/* Eden_Twitter_Favorites */
if (!class_exists('Eden_Twitter_Favorites')) {

    class Eden_Twitter_Favorites extends Eden_Twitter_Base {

        const URL_GET_FAVORITES = 'https://api.twitter.com/1.1/favorites/list.json';
        const URL_FAVORITE_STATUS = 'https://api.twitter.com/1.1/favorites/create.json';
        const URL_UNFAVORITE_STATUS = 'https://api.twitter.com/1.1/favorites/destroy.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function addFavorites($id) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['id'] = $id;
            return $this->_post(self::URL_FAVORITE_STATUS, $this->_query);
        }

        public function getList() {
            return $this->_getResponse(self::URL_GET_FAVORITES, $this->_query);
        }

        public function remove($id) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['id'] = $id;
            return $this->_post(self::URL_UNFAVORITE_STATUS, $this->_query);
        }

        public function setUserId($id) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['screen_name'] = $id;
            }return $this;
        }

        public function setCount($count) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            $this->_query['count'] = $count;
            return $this;
        }

        public function setSinceId($sinceId) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['since_id'] = $sinceId;
            return $this;
        }

        public function setMaxId($maxId) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['max_id'] = $maxId;
            return $this;
        }

        public function setPage($page) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['page'] = $page;
            return $this;
        }

        public function includeEntities() {
            $this->_query['include_entities'] = true;
            return $this;
        }

    }

}
/* Eden_Twitter_Friends */
if (!class_exists('Eden_Twitter_Friends')) {

    class Eden_Twitter_Friends extends Eden_Twitter_Base {

        const URL_FRIENDS = 'https://api.twitter.com/1.1/friends/ids.json';
        const URL_FOLLOWERS = 'https://api.twitter.com/1.1/followers/ids.json';
        const URL_LOOKUP_FRIENDS = 'https://api.twitter.com/1.1/friendships/lookup.json';
        const URL_INCOMING_FRIENDS = 'https://api.twitter.com/1.1/friendships/incoming.json';
        const URL_OUTGOING_FRIENDS = 'https://api.twitter.com/1.1/friendships/outgoing.json';
        const URL_FOLLOW_FRIENDS = 'https://api.twitter.com/1.1/friendships/create.json';
        const URL_UNFOLLOW_FRIENDS = 'https://api.twitter.com/1.1/friendships/destroy.json';
        const URL_UPDATE = 'https://api.twitter.com/1.1/friendships/update.json';
        const URL_SHOW_FRIENDS = 'https://api.twitter.com/1.1/friendships/show.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getFollowing($id = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string', 'null');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['string_name'] = $id;
            }return $this->_getResponse(self::URL_FRIENDS, $this->_query);
        }

        public function getFollowers($id = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string', 'null');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['string_name'] = $id;
            }return $this->_getResponse(self::URL_FOLLOWERS, $this->_query);
        }

        public function follow($id, $notify = false) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int')->argument(2, 'bool');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['screen_name'] = $id;
            }return $this->_post(self::URL_FOLLOW_FRIENDS, $this->_query);
        }

        public function getPendingFollowing() {
            return $this->_getResponse(self::URL_OUTGOING_FRIENDS, $this->_query);
        }

        public function getPendingFollowers() {
            return $this->_getResponse(self::URL_INCOMING_FRIENDS, $this->_query);
        }

        public function getRelationship($id, $target) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int')->argument(2, 'string', 'int');
            if (is_int($id)) {
                $this->_query['source_id'] = $id;
            } else {
                $this->_query['source_screen_name'] = $id;
            }if (is_int($target)) {
                $this->_query['target_id'] = $target;
            } else {
                $this->_query['target_screen_name'] = $target;
            }return $this->_getResponse(self::URL_SHOW_FRIENDS, $this->_query);
        }

        public function getRelationships($id = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string', 'array', 'null');
            if (is_null($id)) {
                return $this->_getResponse(self::URL_LOOKUP_FRIENDS, $this->_query);
            }if (!is_array($id)) {
                $id = func_get_args();
            }if (is_int($id[0])) {
                $this->_query['user_id'] = implode(',', $id);
            } else {
                $this->_query['screen_name'] = implode(',', $id);
            }return $this->_getResponse(self::URL_LOOKUP_FRIENDS, $this->_query);
        }

        public function unfollow($id, $entities = false) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int')->argument(2, 'boolean');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['string_name'] = $id;
            }if ($entities) {
                $this->_query['include_entities'] = $entities;
            }return $this->_post(self::URL_UNFOLLOW_FRIENDS, $this->_query);
        }

        public function update($id, $device = false, $retweets = false) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int')->argument(2, 'bool')->argument(3, 'bool');
            if (is_string($id)) {
                $this->_query['screen_name'] = $id;
            } else {
                $this->_query['user_id'] = $id;
            }if ($device) {
                $this->_query['device'] = 1;
            }if ($retweets) {
                $this->_query['retweets'] = 1;
            }return $this->_post(self::URL_UPDATE, $this->_query);
        }

    }

}
/* Eden_Twitter_Geo */
if (!class_exists('Eden_Twitter_Geo')) {

    class Eden_Twitter_Geo extends Eden_Twitter_Base {

        const URL_GET_PLACE = 'https://api.twitter.com/1.1/geo/id/%s.json';
        const URL_GET_GEOCODE = 'https://api.twitter.com/1.1/geo/reverse_geocode.json';
        const URL_SEARCH = 'https://api.twitter.com/1.1/geo/search.json';
        const URL_GET_SIMILAR_PLACES = 'https://api.twitter.com/1.1/geo/similar_places.json';
        const URL_CREATE_PLACE = 'https://api.twitter.com/1.1/geo/place.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createPlace($name, $contained, $token, $latitude, $longtitude) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'float', 'int')->argument(5, 'float', 'int');
            $this->_query['lat'] = $latitude;
            $this->_query['long'] = $longtitude;
            $this->_query['name'] = $name;
            $this->_query['token'] = $token;
            $this->_query['contained_within'] = $contained;
            return $this->_post(self::URL_CREATE_PLACE, $this->_query);
        }

        public function getGeocode($lat, $long) {
            Eden_Twitter_Error::i()->argument(1, 'float', 'int')->argument(2, 'float', 'int');
            $this->_query['lat'] = $latitude;
            $this->_query['long'] = $longtitude;
            return $this->_getResponse(self::URL_GET_GEOCODE, $this->_query);
        }

        public function getPlace($id) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            return $this->_getResponse(sprintf(self::URL_GET_PLACE, $id));
        }

        public function getSimilarPlaces($latitude, $longtitude, $name) {
            Eden_Twitter_Error::i()->argument(1, 'float', 'int')->argument(2, 'float', 'int')->argument(3, 'string');
            $this->_query['lat'] = $latitude;
            $this->_query['long'] = $longtitude;
            $this->_query['name'] = $name;
            return $this->_getResponse(self::URL_GET_SIMILAR_PLACES, $this->_query);
        }

        public function search($query = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'null');
            $this->_query['query'] = $query;
            return $this->_getResponse(self::URL_SEARCH, $this->_query);
        }

        public function setAccuracy($accuracy) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['accuracy'] = $accuracy;
            return $this;
        }

        public function setAddress($address) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['attribute:street_address'] = $address;
            return $this;
        }

        public function setCallback($callback) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['callback'] = $callback;
            return $this;
        }

        public function setContained($contained) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['contained_within'] = $contained;
            return $this;
        }

        public function setGranularity($granularity) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['granularity'] = $granularity;
            return $this;
        }

        public function setIp($ip) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['ip'] = $ip;
            return $this;
        }

        public function setLatitude($latitude) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'float');
            $this->_query['lat'] = $latitude;
            return $this;
        }

        public function setLongtitude($longtitude) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'float');
            $this->_query['long'] = $longtitude;
            return $this;
        }

        public function setMaxResults($maxResults) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['max_results'] = $maxResults;
            return $this;
        }

    }

}
/* Eden_Twitter_Help */
if (!class_exists('Eden_Twitter_Help')) {

    class Eden_Twitter_Help extends Eden_Twitter_Base {

        const URL_CONFIGURATION = 'https://api.twitter.com/1.1/help/configuration.json';
        const URL_LANGUAGES = 'https://api.twitter.com/1.1/help/languages.json';
        const URL_PRIVACY = 'https://api.twitter.com/1.1/help/privacy.json';
        const URL_TOS = 'https://api.twitter.com/1.1/help/tos.json';
        const URL_RATE_LIMIT = 'https://api.twitter.com/1.1/application/rate_limit_status.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getConfiguration() {
            return $this->_getResponse(self::URL_CONFIGURATION);
        }

        public function getLanguages() {
            return $this->_getResponse(self::URL_LANGUAGES);
        }

        public function getPrivacy() {
            return $this->_getResponse(self::URL_PRIVACY);
        }

        public function getTermsAndCondition() {
            return $this->_getResponse(self::URL_TOS);
        }

        public function getRateLimitStatus($resources = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'null');
            $this->_query['resources'] = $resources;
            return $this->_getResponse(self::URL_RATE_LIMIT, $this->_query);
        }

    }

}
/* Eden_Twitter_List */
if (!class_exists('Eden_Twitter_List')) {

    class Eden_Twitter_List extends Eden_Twitter_Base {

        const URL_ALL_LIST = 'https://api.twitter.com/1.1/lists/list.json';
        const URL_GET_STATUS = 'https://api.twitter.com/1.1/lists/statuses.json';
        const URL_REMOVE_MEMBER = 'https://api.twitter.com/1.1/lists/members/destroy.json';
        const URL_MEMBERSHIP = 'https://api.twitter.com/1.1/lists/memberships.json';
        const URL_SUBSCRIBER = 'https://api.twitter.com/1.1/lists/subscribers.json';
        const URL_CREATE_SUBCRIBER = 'https://api.twitter.com/1.1/lists/subscribers/create.json';
        const URL_SHOW_SUBSCRIBER = 'https://api.twitter.com/1.1/lists/subscribers/show.json';
        const URL_REMOVE_SUBCRIBER = 'https://api.twitter.com/1.1/lists/subscribers/destroy.json';
        const URL_CREATE_ALL = 'https://api.twitter.com/1.1/lists/members/create_all.json';
        const URL_GET_MEMBER = 'https://api.twitter.com/1.1/lists/members/show.json';
        const URL_GET_DETAIL = 'https://api.twitter.com/1.1/lists/members.json';
        const URL_CREATE_MEMBER = 'https://api.twitter.com/1.1/lists/members/create.json';
        const URL_REMOVE = 'https://api.twitter.com/1.1/lists/destroy.json';
        const URL_UPDATE = 'https://api.twitter.com/1.1/lists/update.json';
        const URL_CREATE_USER = 'https://api.twitter.com/1.1/lists/create.json';
        const URL_SHOW = 'https://api.twitter.com/1.1/lists/show.json';
        const URL_GET_SUBSCRITION = 'https://api.twitter.com/1.1/lists/subscriptions.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function addMember($userId, $listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string')->argument(3, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }if (is_int($userId)) {
                $this->_query['user_id'] = $userId;
            } else {
                $this->_query['screen_name'] = $userId;
            }return $this->_post(self::URL_CREATE_MEMBER, $this->_query);
        }

        public function addMembers($listId, $userIds, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'array')->argument(3, 'int', 'string');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (is_int($ownerId)) {
                $this->_query['owner_id'] = $ownerId;
            } else {
                $this->_query['owner_screen_name'] = $ownerId;
            }if (is_int($userIds[0])) {
                $this->_query['user_id'] = implode(',', $userIds);
            } else {
                $this->_query['screen_name'] = implode(',', $userIds);
            }return $this->_post(self::URL_CREATE_ALL, $this->_query);
        }

        public function createList($name) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['name'] = $name;
            return $this->_post(self::URL_CREATE_USER, $this->_query);
        }

        public function getMembers($listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }return $this->_getResponse(self::URL_GET_DETAIL, $this->_query);
        }

        public function getAllLists($id = NULL) {
            Eden_Twitter_Error::i()->argument(2, 'int', 'string', 'null');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['screen_name'] = $id;
            }return $this->_getResponse(self::URL_ALL_LIST, $this->_query);
        }

        public function getList($listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }return $this->_getResponse(self::URL_SHOW, $this->_query);
        }

        public function getMemberships($id = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string', 'null');
            if (!is_null($id)) {
                if (is_int($id)) {
                    $this->_query['user_id'] = $id;
                } else {
                    $this->_query['screen_name'] = $id;
                }
            }return $this->_getResponse(self::URL_MEMBERSHIP, $this->_query);
        }

        public function getTweets($listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }return $this->_getResponse(self::URL_GET_STATUS, $this->_query);
        }

        public function getSubscribers($listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }return $this->_getResponse(self::URL_SUBSCRIBER, $this->_query);
        }

        public function getSubscriptions($id) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['screen_name'] = $id;
            }return $this->_getResponse(self::URL_GET_SUBSCRITION, $this->_query);
        }

        public function filterToOwn() {
            $this->_query['filter_to_owned_lists'] = true;
            return $this;
        }

        public function includeEntities() {
            $this->_query['include_entities'] = true;
            return $this;
        }

        public function includeRts() {
            $this->_query['include_rts'] = true;
            return $this;
        }

        public function isMember($userId, $listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string')->argument(3, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }if (is_int($user_id)) {
                $this->_query['user_id'] = $user_id;
            } else {
                $this->_query['screen_name'] = $user_id;
            }return $this->_getResponse(self::URL_GET_MEMBER, $this->_query);
        }

        public function isSubsciber($userId, $listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string')->argument(3, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }if (is_int($user_id)) {
                $query['user_id'] = $user_id;
            } else {
                $this->_query['screen_name'] = $user_id;
            }return $this->_getResponse(self::URL_SHOW_SUBSCRIBER, $this->_query);
        }

        public function remove($listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string', 'null');
            if (is_int($listId)) {
                $qthis->_uery['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }return $this->_post(self::URL_REMOVE, $this->_query);
        }

        public function removeMember($userId, $listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string')->argument(3, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }if (is_int($user_id)) {
                $this->_query['user_id'] = $ownerId;
            } else {
                $this->_query['screen_name'] = $ownerId;
            }return $this->_post(self::URL_REMOVE_MEMBER, $this->_query);
        }

        public function setCount($count) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['count'] = $count;
            return $this;
        }

        public function setCursor($cursor) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['cursor'] = $cursor;
            return $this;
        }

        public function setMax($max) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['max_id'] = $max;
            return $this;
        }

        public function setPage($perPage) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['per_page'] = $perPage;
            return $this;
        }

        public function setSinceId($sinceId) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['since_id'] = $sinceId;
            return $this;
        }

        public function setDescription($description) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['description'] = $description;
            return $this;
        }

        public function setModeToPrivate() {
            $this->_query['mode'] = 'private';
            return $this;
        }

        public function skipStatus() {
            $this->_query['skip_status'] = true;
            return $this;
        }

        public function subscribe($listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }return $this->_post(self::URL_CREATE_SUBCRIBER, $this->_query);
        }

        public function unsubscribe($listId, $ownerId = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'int', 'string', 'null');
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }return $this->_post(self::URL_REMOVE_SUBCRIBER, $this->_query);
        }

        public function update($listId, $name, $description, $ownerId = NULL, $public = true) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'int', 'string', 'null')->argument(5, 'bool');
            $this->_query['name'] = $name;
            $this->_query['description'] = $description;
            if (is_int($listId)) {
                $this->_query['list_id'] = $listId;
            } else {
                $this->_query['slug'] = $listId;
            }if (!is_null($ownerId)) {
                if (is_int($ownerId)) {
                    $this->_query['owner_id'] = $ownerId;
                } else {
                    $this->_query['owner_screen_name'] = $ownerId;
                }
            }return $this->_post(self::URL_UPDATE, $this->_query);
        }

    }

}
/* Eden_Twitter_Saved */
if (!class_exists('Eden_Twitter_Saved')) {

    class Eden_Twitter_Saved extends Eden_Twitter_Base {

        const URL_SAVED_SEARCHES = 'https://api.twitter.com/1.1/saved_searches/list.json';
        const URL_GET_DETAIL = 'https://api.twitter.com/1.1/saved_searches/show/%d.json';
        const URL_CREATE_SEARCH = 'https://api.twitter.com/1.1/saved_searches/create.json';
        const URL_REMOVE = 'https://api.twitter.com/1.1/saved_searches/destroy/%d.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function createSearch($query) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['query'] = $query;
            return $this->_post(self::URL_CREATE_SEARCH, $this->_query);
        }

        public function getDetail($id) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            return $this->_getResponse(sprintf(self::URL_GET_DETAIL, $id));
        }

        public function getSavedSearches() {
            return $this->_getResponse(self::URL_SAVED_SEARCHES);
        }

        public function remove($id) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            return $this->_post(sprintf(self::URL_REMOVE, $id));
        }

    }

}
/* Eden_Twitter_Search */
if (!class_exists('Eden_Twitter_Search')) {

    class Eden_Twitter_Search extends Eden_Twitter_Base {

        const URL_SEARCH_TWEETS = 'https://api.twitter.com/1.1/search/tweets.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function search($query) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['q'] = $query;
            return $this->_getResponse(self::URL_SEARCH_TWEETS, $this->_query);
        }

        public function setCallback($callback) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['callback'] = $callback;
            return $this;
        }

        public function includeEntities() {
            $this->_query['include_entities'] = true;
            return $this;
        }

        public function setGeocode($geocode) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['geocode'] = $geocode;
            return $this;
        }

        public function setLanguage($language) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['lang'] = $language;
            return $this;
        }

        public function setLocale($locale) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['locale'] = $locale;
            return $this;
        }

        public function setPage($page) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['page'] = $page;
            return $this;
        }

        public function setMixedResultType() {
            $this->_query['result_type'] = 'mixed';
            return $this;
        }

        public function setRecentResultType() {
            $this->_query['result_type'] = 'recent';
            return $this;
        }

        public function setPopularResultType() {
            $this->_query['result_type'] = 'popular';
            return $this;
        }

        public function setRpp($rpp) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            if ($rpp > 100) {
                $rpp = 100;
            }$this->_query['rpp'] = $rpp;
            return $this;
        }

        public function setSinceId($sinceId) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['since_id'] = $sinceId;
            return $this;
        }

        public function showUser() {
            $this->_query['show_user'] = true;
            return $this;
        }

        public function setUntil($until) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int');
            if (is_string($until)) {
                $until = strtotime($until);
            }$until = date('Y-m-d', $until);
            $this->_query['until'] = $until;
            return $this;
        }

    }

}
/* Eden_Twitter_Spam */
if (!class_exists('Eden_Twitter_Spam')) {

    class Eden_Twitter_Spam extends Eden_Twitter_Base {

        const URL_REPORT_SPAM = 'https://api.twitter.com/1.1/users/report_spam.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function reportSpam($id = NULL, $name = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'null')->argument(2, 'string', 'null');
            if (!is_null($id)) {
                $this->_query['user_id'] = $id;
            }if (!is_null($name)) {
                $this->_query['screen_name'] = $name;
            }return $this->_post(self::URL_REPORT_SPAM, $this->_query);
        }

    }

}
/* Eden_Twitter_Streaming */
if (!class_exists('Eden_Twitter_Streaming')) {

    class Eden_Twitter_Streaming extends Eden_Twitter_Base {

        const URL_STREAM_PUBLIC_STATUS = 'https://stream.twitter.com/1.1/statuses/filter.json';
        const URL_STREAM_RANDOM_STATUS = 'https://stream.twitter.com/1.1/statuses/sample.json';
        const URL_STREAM_FIRE_HOSE = 'https://stream.twitter.com/1.1/statuses/firehose.json';
        const URL_STREAM_USER_MESSAGE = 'https://userstream.twitter.com/1.1/user.json';
        const URL_STREAM_SITE = 'https://sitestream.twitter.com/1.1/site.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function streamPublicStatus() {
            return $this->_post(self::URL_STREAM_PUBLIC_STATUS, $this->_query);
        }

        public function streamRandomStatus() {
            return $this->_getResponse(self::URL_STREAM_RANDOM_STATUS, $this->_query);
        }

        public function fireHose() {
            return $this->_getResponse(self::URL_STREAM_FIRE_HOSE, $this->_query);
        }

        public function streamMessage() {
            return $this->_getResponse(self::URL_STREAM_FIRE_HOSE, $this->_query);
        }

        public function streamSite() {
            return $this->_getResponse(self::URL_STREAM_SITE, $this->_query);
        }

        public function streamWithFollowings() {
            $this->_query['with'] = 'followings';
            return $this;
        }

        public function steamWithReplies() {
            $this->_query['replies'] = 'all';
            return $this;
        }

        public function setCount($count) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['count'] = $count;
            return $this;
        }

        public function setFollow($follow) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'array');
            if (is_array($follow)) {
                $this->_query['follow'] = implode(',', $follow);
            } else {
                $this->_query['follow'] = $follow;
            }return $this;
        }

        public function setTrack($track) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'array');
            if (is_array($track)) {
                $this->_query['track'] = implode(',', $track);
            } else {
                $this->_query['track'] = $track;
            }return $this;
        }

        public function setLocation($locations) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'array');
            if (is_array($track)) {
                $this->_query['locations'] = implode(',', $locations);
            } else {
                $this->_query['locations'] = $locations;
            }return $this;
        }

        public function setDelimited() {
            $this->_query['delimited'] = 'length';
            return $this;
        }

        public function setStallWarning() {
            $this->_query['stall_warnings'] = true;
            return $this;
        }

    }

}
/* Eden_Twitter_Suggestions */
if (!class_exists('Eden_Twitter_Suggestions')) {

    class Eden_Twitter_Suggestions extends Eden_Twitter_Base {

        const URL_GET_CATEGORY = 'https://api.twitter.com/1.1/users/suggestions/%s.json';
        const URL_FAVORITES = 'https://api.twitter.com/1.1/favorites/list.json';
        const URL_SUGGESTIONS = 'https://api.twitter.com/1/users/suggestions/%s/members.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getCategory($slug, $lang = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string', 'null');
            if (!is_null($lang)) {
                $this->_query['lang'] = $lang;
            }return $this->_getResponse(sprintf(self::URL_GET_CATEGORY, $slug), $this->_query);
        }

        public function getFavorites($id = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int', 'null');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            }if (is_string($id)) {
                $this->_query['screen_name'] = $id;
            }return $this->_getResponse(self::URL_FAVORITES, $this->_query);
        }

        public function getUserByStatus($slug) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            return $this->_getResponse(sprintf(self::URL_SUGGESTIONS, $slug));
        }

        public function setCount($count) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['count'] = $count;
            return $this;
        }

        public function setSinceId($sinceId) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['since_id'] = $sinceId;
            return $this;
        }

        public function setMaxId($maxId) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['max_id'] = $maxId;
            return $this;
        }

        public function includeEntities() {
            $this->_query['include_entities'] = false;
            return $this;
        }

    }

}
/* Eden_Twitter_Timeline */
if (!class_exists('Eden_Twitter_Timeline')) {

    class Eden_Twitter_Timeline extends Eden_Twitter_Base {

        const URL_TIMELINES_MENTION = 'https://api.twitter.com/1.1/statuses/mentions_timeline.json';
        const URL_TIMELINES_USER = 'https://api.twitter.com/1.1/statuses/user_timeline.json';
        const URL_TIMELINES_HOME = 'https://api.twitter.com/1.1/statuses/home_timeline.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getMentionTimeline() {
            return $this->_getResponse(self::URL_TIMELINES_MENTION, $this->_query);
        }

        public function getUserTimelines($id = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['screen_name'] = $id;
            }return $this->_getResponse(self::URL_TIMELINES_USER, $this->_query);
        }

        public function getYourTimeLine() {
            return $this->_getResponse(self::URL_TIMELINES_MENTION, $this->_query);
        }

        public function setSinceId($sinceId) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            $this->_query['since_id'] = $sinceId;
            return $this;
        }

        public function setCount($count) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            $this->_query['count'] = $count;
            return $this;
        }

        public function setMaxId($maxId) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            $this->_query['max_id'] = $maxId;
            return $this;
        }

        public function trimUser() {
            $this->_query['trim_user'] = true;
            return $this;
        }

        public function excludeReplies() {
            $this->_query['exclude_replies'] = true;
            return $this;
        }

        public function setContributorDetails() {
            $this->_query['contributor_details'] = true;
            return $this;
        }

        public function includeRts() {
            $this->_query['include_rts'] = false;
            return $this;
        }

    }

}
/* Eden_Twitter_Trends */
if (!class_exists('Eden_Twitter_Trends')) {

    class Eden_Twitter_Trends extends Eden_Twitter_Base {

        const URL_TRENDING_PLACE = 'https://api.twitter.com/1.1/trends/place.json';
        const URL_TRENDING_AVAILABLE = 'https://api.twitter.com/1.1/trends/available.json';
        const URL_TRENDING_CLOSEST = 'https://api.twitter.com/1.1/trends/closest.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getPlaceTrending($id) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int');
            $this->_query['id'] = $id;
            return $this->_getResponse(self::URL_TRENDING_PLACE, $this->_query);
        }

        public function getAvailableTrending() {
            return $this->_getResponse(self::URL_TRENDING_AVAILABLE);
        }

        public function getClosestTrending($lat = NULL, $long = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'float', 'null')->argument(2, 'float', 'null');
            if (!is_null($lat)) {
                $this->_query['lat'] = $lat;
            }if (!is_null($long)) {
                $this->_query['long'] = $long;
            }return $this->_getResponse(self::URL_TRENDING_CLOSEST, $this->_query);
        }

    }

}
/* Eden_Twitter_Tweets */
if (!class_exists('Eden_Twitter_Tweets')) {

    class Eden_Twitter_Tweets extends Eden_Twitter_Base {

        const URL_TWEETS_GET_RETWEET = 'https://api.twitter.com/1.1/statuses/retweets/%s.json';
        const URL_TWEETS_GET_TWEET = 'https://api.twitter.com/1.1/statuses/show.json';
        const URL_TWEETS_REMOVE_TWEET = 'https://api.twitter.com/1.1/statuses/destroy/%s.json';
        const URL_TWEETS_TWEET = 'https://api.twitter.com/1.1/statuses/update.json';
        const URL_TWEETS_RETWEET = 'https://api.twitter.com/1.1/statuses/retweet/%s.json';
        const URL_TWEETS_TWEET_MEDIA = 'https://api.twitter.com/1.1/statuses/update_with_media.json';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getRetweet($id) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            return $this->_getResponse(sprintf(self::URL_TWEETS_GET_RETWEET, $id), $this->_query);
        }

        public function getTweet($id) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            $this->_query['id'] = $id;
            return $this->_getResponse(self::URL_TWEETS_GET_TWEET, $this->_query);
        }

        public function removeTweet($id) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            return $this->_post(sprintf(self::URL_TWEETS_REMOVE_TWEET, $id), $this->_query);
        }

        public function tweet($status) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['status'] = $status;
            return $this->_post(self::URL_TWEETS_TWEET, $this->_query);
        }

        public function retweet($tweetId) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            return $this->_post(sprintf(self::URL_TWEETS_RETWEET, $tweetId), $this->_query);
        }

        public function tweetMedia($status, $media) {
            Eden_Twitter_Error::i()->argument(1, 'string')->argument(2, 'string');
            $this->_query['status'] = $status;
            $this->_query['media[]'] = $media;
            return $this->_upload(self::URL_TWEETS_TWEET_MEDIA, $this->_query);
        }

        public function inReplyToStatusId($statusId) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['in_reply_to_status_id'] = $statusId;
            return $this;
        }

        public function setLatitude($latutide) {
            Eden_Twitter_Error::i()->argument(1, 'float');
            $this->_query['lat'] = $latutide;
            return $this;
        }

        public function setLongtitude($longtitude) {
            Eden_Twitter_Error::i()->argument(1, 'float');
            $this->_query['long'] = $longtitude;
            return $this;
        }

        public function setPlaceId($placeId) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['place_id'] = $placeId;
            return $this;
        }

        public function setCount($count) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            if ($count <= 100) {
                $this->_query['count'] = $count;
            } else {
                $this->_query['count'] = 100;
            }return $this;
        }

        public function displayCoordinates() {
            $this->_query['display_coordinates'] = true;
            return $this;
        }

        public function trimUser() {
            $this->_query['trim_user'] = true;
            return $this;
        }

        public function includeEntities() {
            $this->_query['include_entities'] = false;
            return $this;
        }

        public function includeMyRetweet() {
            $this->_query['include_my_retweet'] = true;
            return $this;
        }

        public function possiblySensitive() {
            $this->_query['possibly_sensitive'] = true;
            return $this;
        }

    }

}
/* Eden_Twitter_Users */
if (!class_exists('Eden_Twitter_Users')) {

    class Eden_Twitter_Users extends Eden_Twitter_Base {

        const URL_USERS_SETTING = 'https://api.twitter.com/1.1/account/settings.json';
        const URL_USERS_VERIFY_CREDENTIALS = 'https://api.twitter.com/1.1/account/verify_credentials.json';
        const URL_USERS_UPDATE_DEVICE = 'https://api.twitter.com/1.1/account/update_delivery_device.json';
        const URL_USERS_UPDATE_PROFILE = 'https://api.twitter.com/1.1/account/update_profile.json';
        const URL_USERS_UPDATE_BACKGROUND = 'https://api.twitter.com/1.1/account/update_profile_background_image.json';
        const URL_UPDATE_PROFILE_COLOR = 'https://api.twitter.com/1.1/account/update_profile_colors.json';
        const URL_ACCOUNT_UPLOAD = 'https://api.twitter.com/1.1/account/update_profile_image.json';
        const URL_USERS_BLOCK_LIST = 'https://api.twitter.com/1.1/blocks/list.json';
        const URL_GET_BLOCKING_ID = 'https://api.twitter.com/1.1/blocks/ids.json';
        const URL_CREATE_BLOCKING = 'https://api.twitter.com/1.1/blocks/create.json';
        const URL_REMOVE_BLOCKING = 'https://api.twitter.com/1.1/blocks/destroy.json';
        const URL_LOOK_UP = 'https://api.twitter.com/1.1/users/lookup.json';
        const URL_SEARCH = 'https://api.twitter.com/1/users/search.json';
        const URL_SHOW = 'https://api.twitter.com/1/users/show.json';
        const URL_CONTRIBUTEES = 'https://api.twitter.com/1/users/contributees.json';
        const URL_CONTRIBUTORS = 'https://api.twitter.com/1/users/contributors.json';

        protected $_id = NULL;
        protected $_name = NULL;
        protected $_size = NULL;
        protected $_page = NULL;
        protected $_perpage = NULL;
        protected $_entities = NULL;
        protected $_status = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getAccountSettings() {
            return $this->_getResponse(self::URL_USERS_SETTING);
        }

        public function getCredentials() {
            return $this->_getResponse(self::URL_USERS_VERIFY_CREDENTIALS, $this->_query);
        }

        public function updateDeliveryDevice($device) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            $this->_query['device'] = $device;
            return $this->_post(self::URL_USERS_UPDATE_DEVICE, $this->_query);
        }

        public function updateProfile() {
            return $this->_post(self::URL_USERS_UPDATE_PROFILE, $this->_query);
        }

        public function updateBackgroundImage($image) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['image'] = $image;
            return $this->_upload(self::URL_UPDATE_BACKGROUND, $this->_query);
        }

        public function updateProfileColor() {
            return $this->_post(self::URL_UPDATE_PROFILE_COLOR, $this->_query);
        }

        public function updateProfileImage($image) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['image'] = $image;
            return $this->_upload(self::URL_ACCOUNT_UPLOAD, $this->_query);
        }

        public function getBlockList() {
            return $this->_getResponse(self::URL_USERS_BLOCK_LIST, $this->_query);
        }

        public function getBlockedUserIds($stringify = false) {
            Eden_Twitter_Error::i()->argument(1, 'bool');
            $this->_query['stringify_ids'] = $stringify;
            return $this->_getResponse(self::URL_GET_BLOCKING_ID, $this->_query);
        }

        public function blockUser($id) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['screen_name'] = $id;
            }return $this->_post(self::URL_CREATE_BLOCKING, $this->_query);
        }

        public function unblock($id) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'int');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['screen_name'] = $id;
            }return $this->_post(self::URL_REMOVE_BLOCKING, $this->_query);
        }

        public function lookupFriends() {
            if (is_int($this->_query['user_id'])) {
                $id = explode(',', $this->_query['user_id']);
                $id = array();
                $this->_query['user_id'] = $id;
            }if (is_string($this->_query['screen_name'])) {
                $name = explode(',', $this->_query['screen_name']);
                $name = array();
                $this->_query['screen_name'] = $name;
            }return $this->_getResponse(self::URL_LOOK_UP, $this->_query);
        }

        public function getContributees($id = NULL, $name = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'null')->argument(2, 'string', 'null');
            if ($this->_id) {
                $this->_query['user_id'] = $id;
            }if ($this->_name) {
                $this->_query['screen_name'] = $name;
            }return $this->_getResponse(self::URL_CONTRIBUTEES, $this->_query);
        }

        public function getContributors($id = NULL, $name = NULL) {
            Eden_Twitter_Error::i()->argument(1, 'string', 'null')->argument(2, 'string', 'null');
            if ($this->_id) {
                $this->_query['user_id'] = $id;
            }if ($this->_name) {
                $this->_query['screen_name'] = $name;
            }return $this->_getResponse(self::URL_CONTRIBUTORS, $this->_query);
        }

        public function getDetail($id) {
            Eden_Twitter_Error::i()->argument(1, 'int', 'string');
            if (is_int($id)) {
                $this->_query['user_id'] = $id;
            } else {
                $this->_query['screen_name'] = $id;
            }return $this->_getResponse(self::URL_SHOW, $this->_query);
        }

        public function search($search) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['q'] = $search;
            return $this->_getResponse(self::URL_SEARCH, $this->_query);
        }

        public function setName($name) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['name'] = $name;
            return $this;
        }

        public function setUrl($url) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['url'] = $url;
            return $this;
        }

        public function setDescription($description) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['description'] = $description;
            return $this;
        }

        public function setLocation($location) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['location'] = $location;
            return $this;
        }

        public function setToTile() {
            $this->_query['tile'] = true;
            return $this;
        }

        public function disableProfileBackground() {
            $this->_query['use'] = false;
            return $this;
        }

        public function setBackgroundColor($background) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['profile_background_color'] = $backgroud;
            return $this;
        }

        public function setBorderColor($border) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['profile_sidebar_border_color'] = $border;
            return $this;
        }

        public function setFillColor($fill) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['profile_sidebar_fill_color'] = $fill;
            return $this;
        }

        public function setLinkColor($link) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['profile_link_color'] = $link;
            return $this;
        }

        public function setTextColor($textColor) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['profile_text_color'] = $textColor;
            return $this;
        }

        public function includeEntities() {
            $this->_query['include_entities'] = true;
            return $this;
        }

        public function setUserId($id) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['user_id'] = $id;
            return $this;
        }

        public function setScreenName($name) {
            Eden_Twitter_Error::i()->argument(1, 'string');
            $this->_query['screen_name'] = $name;
            return $this;
        }

        public function setPage($page) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['page'] = $page;
            return $this;
        }

        public function setPerpage($perPage) {
            Eden_Twitter_Error::i()->argument(1, 'int');
            $this->_query['per_page'] = $perPage;
            return $this;
        }

        public function skipStatus() {
            $this->_query['skip_status'] = true;
            $this->_status = true;
            return $this;
        }

    }

}
/* Eden_Tumblr */

if (!class_exists('Eden_Paypal_Error')) {

    class Eden_Paypal_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Paypal_Base */
if (!class_exists('Eden_Paypal_Base')) {

    class Eden_Paypal_Base extends \Eden {

        const VERSION = '84.0';
        const TEST_URL = 'https://api-3t.sandbox.paypal.com/nvp';
        const LIVE_URL = 'https://api-3t.paypal.com/nvp';
        const SANDBOX_URL = 'https://test.authorize.net/gateway/transact.dll';

        protected $_meta = array();
        protected $_url = NULL;
        protected $_user = NULL;
        protected $_password = NULL;
        protected $_signature = NULL;
        protected $_certificate = NULL;

        public function __construct($user, $password, $signature, $certificate, $live = false) {
            $this->_user = $user;
            $this->_password = $password;
            $this->_signature = $signature;
            $this->_certificate = $certificate;
            $this->_url = self::TEST_URL;
            $this->_baseUrl = self::TEST_URL;
            if ($live) {
                $this->_url = self::LIVE_URL;
                $this->_baseUrl = self::LIVE_URL;
            }
        }

        public function getMeta() {
            return $this->_meta;
        }

        protected function _accessKey($array) {
            foreach ($array as $key => $val) {
                if (is_array($val)) {
                    $array[$key] = $this->_accessKey($val);
                }if ($val == false || $val == NULL || empty($val) || !$val) {
                    unset($array[$key]);
                }
            }return $array;
        }

        protected function _request($method, array $query = array(), $post = true) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $default = array('USER' => $this->_user, 'PWD' => $this->_password, 'SIGNATURE' => $this->_signature, 'VERSION' => self::VERSION, 'METHOD' => $method);
            $query = http_build_query($query + $default);
            $curl = Eden_Curl::i()->setUrl($this->_baseUrl)->setVerbose(true)->setCaInfo($this->_certificate)->setPost(true)->setPostFields($query);
            $response = $curl->getQueryResponse();
            $this->_meta['url'] = $this->_baseUrl;
            $this->_meta['query'] = $query;
            $this->_meta['curl'] = $curl->getMeta();
            $this->_meta['response'] = $response;
            return $response;
        }

    }

}
/* Eden_Paypal_Authorization */
if (!class_exists('Eden_Paypal_Authorization')) {

    class Eden_Paypal_Authorization extends Eden_Paypal_Base {

        const DO_AUTHORIZATION = 'DoAuthorization';
        const DO_CAPTURE = 'DoCapture';
        const DO_REAUTHORIZATION = 'DoReauthorization';
        const DO_VOID = 'DoVoid';
        const TRANSACTION_ID = 'TRANSACTIONID';
        const AUTHORIZATION_ID = 'AUTHORIZATIONID';
        const ENTITY = 'TRANSACTIONENTITY';
        const ORDER = 'Order';
        const ACK = 'ACK';
        const SUCCESS = 'Success';
        const AMOUNT = 'AMT';
        const CURRENCY = 'CURRENCYCODE';
        const COMPLETE_TYPE = 'COMPLETETYPE';
        const COMPLETE = 'COMPLETE';
        const NO_COMPLETE = 'NoComplete';
        const NOTE = 'NOTE';

        protected $_amout = NULL;
        protected $_currency = NULL;
        protected $_completeType = NULL;
        protected $_note = NULL;
        protected $_transactionId = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function doAuthorization() {
            $query = array(self::TRANSACTION_ID => $this->_transactionId, self::AMOUNT => $this->_amount, self::ENTITY => self::ORDER, self::CURRENCY => $this->_currency);
            $response = $this->_request(self::DO_AUTHORIZATION, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response[self::TRANSACTION_ID];
            }return $response;
        }

        public function doCapture() {
            $query = array(self::AUTHORIZATION_ID => $this->_transactionId, self::AMOUNT => $this->_amount, self::CURRENCY => $this->_currency, self::COMPLETE_TYPE => $this->_completeType, self::NOTE => $this->_note);
            $response = $this->_request(self::DO_CAPTURE, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response[self::AUTHORIZATION_ID];
            }return $response;
        }

        public function doReAuthorization() {
            $query = array(self::AUTHORIZATION_ID => $this->_transactionId, self::AMOUNT => $this->_amount, self::CURRENCY => $this->_currency);
            $response = $this->_request(self::DO_REAUTHORIZATION, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response[self::AUTHORIZATION_ID];
            }return $response;
        }

        public function doVoid() {
            $query = array(self::AUTHORIZATION_ID => $this->_transactionId, self::NOTE => $this->_note);
            $response = $this->_request(self::DO_VOID, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response[self::AUTHORIZATION_ID];
            }return $response;
        }

        public function setAmount($amount) {
            Eden_Paypal_Error::i()->argument(1, 'int', 'float');
            $this->_amount = $amount;
            return $this;
        }

        public function setComplete() {
            $this->_completeType = self::COMPLETE;
            return $this;
        }

        public function setCurrency($currency) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_currency = $currency;
            return $this;
        }

        public function setNoComplete() {
            $this->_completeType = self::NO_COMPLETE;
            return $this;
        }

        public function setNote($note) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_note = $note;
            return $this;
        }

        public function setTransactionId($transactionId) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_transactionId = $transactionId;
            return $this;
        }

    }

}
/* Eden_Paypal_Billing */
if (!class_exists('Eden_Paypal_Billing')) {

    class Eden_Paypal_Billing extends Eden_Paypal_Base {

        const SET_AGREEMENT = 'SetCustomerBillingAgreement';
        const GET_AGREEMENT = 'GetBillingAgreementCustomerDetails';
        const TOKEN = 'TOKEN';
        const RETURN_URL = 'RETURNURL';
        const CANCEL_URL = 'CANCELURL';
        const ANY = 'Any';
        const INSTANT_ONLY = 'InstantOnly';
        const ACK = 'ACK';
        const SUCCESS = 'Success';
        const BILLING_TYPE = 'L_BILLINGTYPEn';
        const BILLING_DESC = 'L_BILLINGAGREEMENTDESCRIPTIONn';
        const PAYMENT_TYPE = 'L_PAYMENTTYPEn';
        const AGREEMENT_CUSTOM = 'L_BILLINGAGREEMENTCUSTOMn';
        const AMOUNT = 'AMT';

        protected $_token = NULL;
        protected $_amout = NULL;
        protected $_currency = NULL;
        protected $_completeType = NULL;
        protected $_billingType = NULL;
        protected $_billingDesc = NULL;
        protected $_paymentType = NULL;
        protected $_agreementCustom = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getResponse($return, $cancel) {
            Eden_Paypal_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = array(self::RETURN_URL => $return, self::CANCEL_URL => $cancel, self::BILLING_TYPE => $this->_billingType, self::BILLING_DESC => $this->_billingDesc, self::PAYMENT_TYPE => $this->_paymentType, self::AGREEMENT_CUSTOM => $this->_agreementCustom);
            $response = $this->_request(self::SET_AGREEMENT, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                $this->_token = $response[self::TOKEN];
                if ($this->_token) {
                    return $this->_getAgreement();
                }
            }return $response;
        }

        public function setAgreementCustom($agreementCustom) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_agreementCustom = $agreementCustom;
            return $this;
        }

        public function setBillingDesc($billingDesc) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_billingDesc = $billingDesc;
            return $this;
        }

        public function setBillingType($billingType) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_billingType = $billingType;
            return $this;
        }

        public function setToAny() {
            $this->_paymentType = self::ANY;
            return $this;
        }

        public function setToInstantOnly() {
            $this->_paymentType = self::INSTANT_ONLY;
            return $this;
        }

        protected function _getAgreement() {
            $query = array(self::TOKEN => $this->_token);
            return $this->_request(self::GET_AGREEMENT, $query);
        }

    }

}
/* Eden_Paypal_Checkout */
if (!class_exists('Eden_Paypal_Checkout')) {

    class Eden_Paypal_Checkout extends Eden_Paypal_Base {

        const TEST_URL_CHECKOUT = 'https://www.sandbox.paypal.com/cgi-bin/webscr?cmd=_express-checkout&token=%s';
        const LIVE_URL = 'https://www.paypal.com/webscr?cmd=_express-checkout&token=%s';
        const SET_METHOD = 'SetExpressCheckout';
        const GET_METHOD = 'GetExpressCheckoutDetails';
        const DO_METHOD = 'DoExpressCheckoutPayment';
        const DO_ADDRESS_VERIFY = 'AddressVerify';
        const CALL_BACK = 'Callback';
        const GET_BALANCE = 'GetBalance';
        const MASS_PAYMENT = 'MassPay';
        const GET_DETAIL = 'GetPalDetails';
        const SUCCESS = 'Success';
        const ACK = 'ACK';
        const TOKEN = 'TOKEN';
        const SALE = 'Sale';
        const ERROR = 'L_LONGMESSAGE0';
        const RETURN_URL = 'RETURNURL';
        const CANCEL_URL = 'CANCELURL';
        const TOTAL_AMOUNT = 'PAYMENTREQUEST_0_AMT';
        const SHIPPING_AMOUNT = 'PAYMENTREQUEST_0_SHIPPINGAMT';
        const CURRENCY = 'PAYMENTREQUEST_0_CURRENCYCODE';
        const ITEM_AMOUNT = 'PAYMENTREQUEST_0_ITEMAMT';
        const ITEM_NAME = 'L_PAYMENTREQUEST_0_NAME0';
        const ITEM_DESCRIPTION = 'L_PAYMENTREQUEST_0_DESC0';
        const ITEM_AMOUNT2 = 'L_PAYMENTREQUEST_0_AMT0';
        const QUANTITY = 'L_PAYMENTREQUEST_0_QTY0';
        const EMAIL = 'EMAIL';
        const STREET = 'STREET';
        const ZIP = 'ZIP';
        const RETURN_CURRENCIES = 'RETURNALLCURRENCIES';
        const EMAIL_SUBJECT = 'EMAILSUBJECT';
        const SOLUTION_TYPE = 'SOLUTIONTYPE';
        const PAYMENT_ACTION = 'PAYMENTACTION';
        const PAYER_ID = 'PAYERID';
        const TRANSACTION_ID = 'PAYMENTINFO_0_TRANSACTIONID';

        protected $_callBack = false;
        protected $_currencies = 0;
        protected $_amount = NULL;
        protected $_shippingAmount = NULL;
        protected $_currency = NULL;
        protected $_itemAmount = NULL;
        protected $_itemName = NULL;
        protected $_itemDescription = NULL;
        protected $_quantity = NULL;
        protected $_email = NULL;
        protected $_street = NULL;
        protected $_zip = NULL;
        protected $_emailSubject = NULL;
        protected $_solutionType = 'Sole';

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function __construct($user, $password, $signature, $certificate, $live = false) {
            parent::__construct($user, $password, $signature, $certificate, $live);
            $this->_url = self::TEST_URL_CHECKOUT;
            if ($live) {
                $this->_url = self::LIVE_URL;
            }
        }

        public function checkAddress() {
            $query = array(self::EMAIL => $this->_email, self::STREET => $this->_street, self::ZIP => $this->_zip);
            $response = $this->_request(self::DO_ADDRESS_VERIFY, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response;
            }return $response;
        }

        public function doMassPayment() {
            $query = array(self::EMAIL_SUBJECT => $this->_emailSubject, self::CURRENCY => $this->_currency);
            return $this->_request(self::MASS_PAYMENT, $query);
        }

        public function getBalance() {
            $query = array(self::RETURN_CURRENCIES => $this->_currencies);
            return $this->_request(self::GET_BALANCE, $query);
        }

        public function getDetail() {
            return $this->_request(self::GET_DETAIL);
        }

        public function getResponse($return, $cancel) {
            Eden_Paypal_Error::i()->argument(1, 'string')->argument(2, 'string');
            $query = array('PAYMENTREQUEST_0_PAYMENTACTION' => 'Authorization', self::SOLUTION_TYPE => $this->_solutionType, self::TOTAL_AMOUNT => $this->_amount, self::RETURN_URL => $return, self::CANCEL_URL => $cancel, self::SHIPPING_AMOUNT => $this->_shippingAmount, self::CURRENCY => $this->_currency, self::ITEM_AMOUNT => $this->_itemAmount, self::ITEM_NAME => $this->_itemName, self::ITEM_DESCRIPTION => $this->_itemDescription, self::ITEM_AMOUNT2 => $this->_itemAmount, self::QUANTITY => $this->_quantity,);
            $response = $this->_request(self::SET_METHOD, $query, false);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                if ($this->_callBack) {
                    $this->_token = $response[self::TOKEN];
                    return $this->_getCallback();
                }
            }return $response;
        }

        public function getTransactionId($payerId) {
            $this->_payer = $payerId;
            if (!$this->_token) {
                return NULL;
            }return $this->_getTransactionId();
        }

        public function setAmount($amount) {
            Eden_Paypal_Error::i()->argument(1, 'integer', 'float');
            $this->_amount = $amount;
            return $this;
        }

        public function setCallBack() {
            $this->_callBack = 'true';
            return $this;
        }

        public function setSolutionType($solutioType = 'Sole') {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_solutionType = $solutioType;
            return $this;
        }

        public function setCurrencies() {
            $this->_currencies = 1;
            return $this;
        }

        public function setCurrency($currency) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_currency = $currency;
            return $this;
        }

        public function setEmail($email) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_email = $email;
            return $this;
        }

        public function setEmailSubject($emailSubject) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_emailSubject = $emailSubject;
            return $this;
        }

        public function setItemAmount($itemAmount) {
            Eden_Paypal_Error::i()->argument(1, 'integer', 'float');
            $this->_itemAmount = $itemAmount;
            return $this;
        }

        public function setItemDescription($itemDescription) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_itemDescription = $itemDescription;
            return $this;
        }

        public function setItemName($itemName) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_itemName = $itemName;
            return $this;
        }

        public function setQuantity($quantity) {
            Eden_Paypal_Error::i()->argument(1, 'int');
            $this->_quantity = $quantity;
            return $this;
        }

        public function setShippingAmount($shippingAmount) {
            Eden_Paypal_Error::i()->argument(1, 'integer', 'float');
            $this->_shippingAmount = $shippingAmount;
            return $this;
        }

        public function setStreet($street) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_street = $street;
            return $this;
        }

        public function setToken($token, $redirect = false) {
            $this->_token = $token;
            if ($redirect == true) {
                header('Location: ' . sprintf($this->_url, urlencode($this->_token)));
                return;
            }return $this;
        }

        public function setZip($zip) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_zip = $zip;
            return $this;
        }

        protected function _getCallback() {
            $query = array(self::CURRENCY => $this->_currency, self::TOKEN => $this->_token);
            return $this->_request(self::CALL_BACK, $query);
        }

        protected function _getTransactionId() {
            $checkoutDetails = $this->_request(self::GET_METHOD, array(self::TOKEN => $this->_token));
            $query = array(self::TOKEN => $this->_token, self::PAYMENT_ACTION => self::SALE, self::PAYER_ID => $this->_payer, self::TOTAL_AMOUNT => $this->_amount, self::CURRENCY => $this->_currency);
            $response = $this->_request(self::DO_METHOD, $query);
            return $response;
        }

    }

}
/* Eden_Paypal_Direct */
if (!class_exists('Eden_Paypal_Direct')) {

    class Eden_Paypal_Direct extends Eden_Paypal_Base {

        const DIRECT_PAYMENT = 'DoDirectPayment';
        const NON_REFERENCED_CREDIT = 'DoNonReferencedCredit';
        const TRANSACTION_ID = 'TRANSACTIONID';
        const SALE = 'sale';
        const ACK = 'ACK';
        const SUCCESS = 'Success';
        const REMOTE_ADDRESS = 'REMOTE_ADDR';
        const IP_ADDRESS = 'IPADDRESS';
        const PAYMENT_ACTION = 'PAYMENTACTION';
        const CARD_TYPE = 'CREDITCARDTYPE';
        const CARD_NUMBER = 'ACCT';
        const EXPIRATION_DATE = 'EXPDATE';
        const CVV = 'CVV2';
        const FIRST_NAME = 'FIRSTNAME';
        const LAST_NAME = 'LASTNAME';
        const EMAIL = 'EMAIL';
        const COUNTRY_CODE = 'COUNTRYCODE';
        const STATE = 'STATE';
        const CITY = 'CITY';
        const STREET = 'STREET';
        const ZIP = 'ZIP';
        const AMOUNT = 'AMT';
        const CURRENCY = 'CURRENCYCODE';

        protected $_nonReferencedCredit = false;
        protected $_profileId = NULL;
        protected $_cardType = NULL;
        protected $_cardNumber = NULL;
        protected $_expirationDate = NULL;
        protected $_cvv2 = NULL;
        protected $_firstName = NULL;
        protected $_lastName = NULL;
        protected $_email = NULL;
        protected $_countryCode = NULL;
        protected $_state = NULL;
        protected $_city = NULL;
        protected $_street = NULL;
        protected $_zip = NULL;
        protected $_amout = NULL;
        protected $_currency = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getResponse() {
            $query = array(self::IP_ADDRESS => $_SERVER[self::REMOTE_ADDRESS], self::PAYMENT_ACTION => self::SALE, self::CARD_TYPE => $this->_cardType, self::CARD_NUMBER => $this->_cardNumber, self::EXPIRATION_DATE => $this->_expirationDate, self::CVV => $this->_cvv2, self::FIRST_NAME => $this->_firstName, self::LAST_NAME => $this->_lastName, self::EMAIL => $this->_email, self::COUNTRY_CODE => $this->_countryCode, self::STATE => $this->_state, self::CITY => $this->_city, self::STREET => $this->_street, self::ZIP => $this->_zip, self::AMOUNT => $this->_amount, self::CURRENCY => $this->_currency);
            if ($this->_setNonReferencedCredit) {
                return $this->_setNonReferencedCredit($query);
            }return $this->_setDirectPayment($query);
        }

        public function setAmount($amount) {
            Eden_Paypal_Error::i()->argument(1, 'int', 'float');
            $this->_amount = $amount;
            return $this;
        }

        public function setCardNumber($cardNumber) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_cardNumber = $cardNumber;
            return $this;
        }

        public function setCardType($cardType) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_cardType = $cardType;
            return $this;
        }

        public function setCity($city) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_city = $city;
            return $this;
        }

        public function setCountryCode($countryCode) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_countryCode = $countryCode;
            return $this;
        }

        public function setCurrency($currency) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_currency = $currency;
            return $this;
        }

        public function setCvv2($cvv2) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_cvv2 = $cvv2;
            return $this;
        }

        public function setEmail($email) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_email = $email;
            return $this;
        }

        public function setExpirationDate($expirationDate) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_expirationDate = $expirationDate;
            return $this;
        }

        public function setFirstName($firstName) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_firstName = $firstName;
            return $this;
        }

        public function setLastName($lastName) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_lastName = $lastName;
            return $this;
        }

        public function setNonReferencedCredit() {
            $this->_setNonReferencedCredit = 'true';
            return $this;
        }

        public function setState($state) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_state = $state;
            return $this;
        }

        public function setStreet($street) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_street = $street;
            return $this;
        }

        public function setZip($zip) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_zip = $zip;
            return $this;
        }

        protected function _setDirectPayment($query) {
            Eden_Paypal_Error::i()->argument(1, 'array');
            $response = $this->_request(self::DIRECT_PAYMENT, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response[self::TRANSACTION_ID];
            }return $response;
        }

        protected function _setNonReferencedCredit($query) {
            Eden_Paypal_Error::i()->argument(1, 'array');
            $response = $this->_request(self::NON_REFERENCED_CREDIT, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response[self::TRANSACTION_ID];
            }return $response;
        }

    }

}
/* Eden_Paypal_Recurring */
if (!class_exists('Eden_Paypal_Recurring')) {

    class Eden_Paypal_Recurring extends Eden_Paypal_Base {

        const RECURRING_PAYMENT = 'CreateRecurringPaymentsProfile';
        const GET_DETAIL = 'GetRecurringPaymentsProfileDetails';
        const MANAGE_STATUS = 'ManageRecurringPaymentsProfileStatus';
        const BILL_AMOUNT = 'BillOutstandingAmount';
        const PROFILE_ID = 'PROFILEID';
        const SALE = 'sale';
        const ACK = 'ACK';
        const SUCCESS = 'Success';
        const ERROR = 'L_LONGMESSAGE0';
        const REMOTE_ADDRESS = 'REMOTE_ADDR';
        const IP_ADDRESS = 'IPADDRESS';
        const PAYMENT_ACTION = 'PAYMENTACTION';
        const DAY = 'Day';
        const WEEK = 'Week';
        const SEMI_MONTH = 'SemiMonth';
        const MONTH = 'Month';
        const YEAR = 'Year';
        const CANCEL = 'Cancel';
        const SUSPEND = 'Suspend';
        const REACTIVATE = 'Reactivate';
        const CARD_TYPE = 'CREDITCARDTYPE';
        const CARD_NUMBER = 'ACCT';
        const EXPIRATION_DATE = 'EXPDATE';
        const CVV = 'CVV2';
        const FIRST_NAME = 'FIRSTNAME';
        const LAST_NAME = 'LASTNAME';
        const EMAIL = 'EMAIL';
        const COUNTRY_CODE = 'COUNTRYCODE';
        const STATE = 'STATE';
        const CITY = 'CITY';
        const STREET = 'STREET';
        const ZIP = 'ZIP';
        const AMOUNT = 'AMT';
        const CURRENCY = 'CURRENCYCODE';
        const DESCRIPTION = 'DESC';
        const START_DATE = 'PROFILESTARTDATE';
        const BILLING_PERIOD = 'BILLINGPERIOD';
        const BILLING_FREQUENCY = 'BILLINGFREQUENCY';

        protected $_profileId = NULL;
        protected $_cardType = NULL;
        protected $_cardNumber = NULL;
        protected $_expirationDate = NULL;
        protected $_cvv2 = NULL;
        protected $_firstName = NULL;
        protected $_lastName = NULL;
        protected $_email = NULL;
        protected $_countryCode = NULL;
        protected $_state = NULL;
        protected $_city = NULL;
        protected $_street = NULL;
        protected $_zip = NULL;
        protected $_amout = NULL;
        protected $_currency = NULL;
        protected $_action = NULL;
        protected $_note = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function cancel() {
            $this->_action = self::CANCEL;
            return $this;
        }

        public function getBilling() {
            $query = array(self::PROFILE_ID => $this->_profileId, self::AMOUNT => $this->_amount, self::NOTE => $this->_note);
            $response = $this->_request(self::BILL_AMOUNT, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response;
            }return $response;
        }

        public function getResponse() {
            $query = array(self::IP_ADDRESS => $_SERVER[self::REMOTE_ADDRESS], self::PAYMENT_ACTION => self::SALE, self::CARD_TYPE => $this->_cardType, self::CARD_NUMBER => $this->_cardNumber, self::EXPIRATION_DATE => $this->_expirationDate, self::CVV => $this->_cvv2, self::FIRST_NAME => $this->_firstName, self::LAST_NAME => $this->_lastName, self::EMAIL => $this->_email, self::COUNTRY_CODE => $this->_countryCode, self::STATE => $this->_state, self::CITY => $this->_city, self::STREET => $this->_street, self::ZIP => $this->_zip, self::AMOUNT => $this->_amount, self::CURRENCY => $this->_currency, self::DESCRIPTION => $this->_description, self::START_DATE => date('Y-m-d H:i:s'), self::BILLING_PERIOD => $this->_billingPeriod, self::BILLING_FREQUENCY => $this->_billingFrequency);
            $response = $this->_request(self::RECURRING_PAYMENT, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                $this->_profileId = $response[self::PROFILE_ID];
                return $this->_getDetails();
            }return $response;
        }

        public function getStatus() {
            $query = array(self::PROFILE_ID => $this->_profileId, self::ACTION => $this->_action, self::NOTE => $this->_note);
            $response = $this->_request(self::MANAGE_STATUS, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response;
            }return $response;
        }

        public function reactivate() {
            $this->_action = self::REACTIVATE;
            return $this;
        }

        public function setAmount($amount) {
            Eden_Paypal_Error::i()->argument(1, 'int', 'float');
            $this->_amount = $amount;
            return $this;
        }

        public function setBillingFrequency($billingFrequency) {
            Eden_Paypal_Error::i()->argument(1, 'int');
            $this->_billingFrequency = $billingFrequency;
            return $this;
        }

        public function setCardNumber($cardNumber) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_cardNumber = $cardNumber;
            return $this;
        }

        public function setCardType($cardType) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_cardType = $cardType;
            return $this;
        }

        public function setCity($city) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_city = $city;
            return $this;
        }

        public function setCountryCode($countryCode) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_countryCode = $countryCode;
            return $this;
        }

        public function setCurrency($currency) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_currency = $currency;
            return $this;
        }

        public function setCvv2($cvv2) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_cvv2 = $cvv2;
            return $this;
        }

        public function setDay() {
            $this->_billingPeriod = self::DAY;
            return $this;
        }

        public function setDescription($description) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_description = $description;
            return $this;
        }

        public function setEmail($email) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_email = $email;
            return $this;
        }

        public function setExpirationDate($expirationDate) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_expirationDate = $expirationDate;
            return $this;
        }

        public function setFirstName($firstName) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_firstName = $firstName;
            return $this;
        }

        public function setLastName($lastName) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_lastName = $lastName;
            return $this;
        }

        public function setMonth() {
            $this->_billingPeriod = self::MONTH;
            return $this;
        }

        public function setNote($note) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_note = $note;
            return $this;
        }

        public function setProfileId($profileId) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_profileId = $profileId;
            return $this;
        }

        public function setSemiMonth() {
            $this->_billingPeriod = self::SEMI_MONTH;
            return $this;
        }

        public function setState($state) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_state = $state;
            return $this;
        }

        public function setStatus($status) {
            $this->_status = $status;
            return $this;
        }

        public function setStreet($street) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_street = $street;
            return $this;
        }

        public function setWeek() {
            $this->_billingPeriod = self::WEEK;
            return $this;
        }

        public function setYear() {
            $this->_billingPeriod = self::YEAR;
            return $this;
        }

        public function setZip($zip) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_zip = $zip;
            return $this;
        }

        public function suspend() {
            $this->_action = self::SUSPEND;
            return $this;
        }

        protected function _getDetails() {
            $query = array(self::PROFILE_ID => $this->_profileId);
            $response = $this->_request(self::GET_DETAIL, $query);
            if (isset($response[self::ACK]) && $response[self::ACK] == self::SUCCESS) {
                return $response;
            }return $response;
        }

    }

}
/* Eden_Paypal_Transaction */
if (!class_exists('Eden_Paypal_Transaction')) {

    class Eden_Paypal_Transaction extends Eden_Paypal_Base {

        const GET_DETAIL = 'GetTransactionDetails';
        const MANAGE_STATUS = 'ManagePendingTransactionStatus';
        const REFUND_TRANSACTION = 'RefundTransaction';
        const SEARCH = 'TransactionSearch';
        const ACTION = 'ACTION';
        const REFUND_TYPE = 'REFUNDTYPE';
        const STORE_ID = 'STOREID';
        const START = 'STARTDATE';
        const END = 'ENDDATE';
        const EMAIL = 'EMAIL';
        const RECEIVER = 'RECEIVER';
        const RECEIPT_ID = 'RECEIPTID';
        const TRANSACTION_ID = 'TRANSACTIONID';
        const CARD_NUMBER = 'ACCT';
        const AMOUNT = 'AMT';
        const CURRENCY = 'CURRENCYCODE';
        const STATUS = 'STATUS';
        const NOTE = 'NOTE';

        protected $_action = NULL;
        protected $_refundType = NULL;
        protected $_amount = NULL;
        protected $_currency = NULL;
        protected $_note = NULL;
        protected $_storeId = NULL;
        protected $_start = NULL;
        protected $_end = NULL;
        protected $_email = NULL;
        protected $_receiver = NULL;
        protected $_receiptId = NULL;
        protected $_transactionId = NULL;
        protected $_cardNumber = NULL;
        protected $_status = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getDetail() {
            $query = array(self::TRANSACTION_ID => $this->_transactionId);
            $response = $this->_request(self::GET_DETAIL, $query);
            return $response;
        }

        public function manageStatus() {
            $query = array(self::TRANSACTION_ID => $this->_transactionId, self::ACTION => $this->_action);
            $response = $this->_request(self::MANAGE_STATUS, $query);
            return $response;
        }

        public function refundTransaction() {
            $query = array(self::TRANSACTION_ID => $this->_transactionId, self::REFUND_TYPE => $this->_refundType, self::AMOUNT => $this->_amount, self::CURRENCY => $this->_currency, self::NOTE => $this->_note, self::STORE_ID => $this->_storeId);
            $response = $this->_request(self::REFUND_TRANSACTION, $query);
            return $response;
        }

        public function search() {
            $query = array(self::START => $this->_start, self::END => $this->_end, self::EMAIL => $this->_email, self::RECEIVER => $this->_receiver, self::RECEIPT_ID => $this->_receiptId, self::TRANSACTION_ID => $this->_transactionId, self::CARD_NUMBER => $this->_cardNumber, self::AMOUNT => $this->_amount, self::CURRENCY => $this->_currency, self::STATUS => $this->_status);
            $response = $this->_request(self::SEARCH, $query);
            return $response;
        }

        public function setAction($action) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_action = $action;
            return $this;
        }

        public function setAmount($amount) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_amount = $amount;
            return $this;
        }

        public function setCardNumber($cardNumber) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_cardNumber = $cardNumber;
            return $this;
        }

        public function setCurrency($currency) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_currency = $currency;
            return $this;
        }

        public function setEmail($email) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_email = $email;
            return $this;
        }

        public function setEndDate($end) {
            $date = strtotime($end);
            $this->_end = gmdate('Y-m-d\TH:i:s\Z', $date);
            return $this;
        }

        public function setNote($note) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_note = $note;
            return $this;
        }

        public function setReceiptId($receiptId) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_receiptId = $receiptId;
            return $this;
        }

        public function setReceiver($receiver) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_receiver = $receiver;
            return $this;
        }

        public function setRefundType($refundType) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_refundType = $refundType;
            return $this;
        }

        public function setStartDate($start) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $date = strtotime($start);
            $this->_start = gmdate('Y-m-d\TH:i:s\Z', $date);
            return $this;
        }

        public function setStatus($status) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_status = $status;
            return $this;
        }

        public function setStoreId($storeId) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_storeId = $storeId;
            return $this;
        }

        public function setTransactionId($transactionId) {
            Eden_Paypal_Error::i()->argument(1, 'string');
            $this->_transactionId = $transactionId;
            return $this;
        }

    }

}
/* Eden_Paypal */
if (!class_exists('Eden_Paypal')) {

    class Eden_Paypal extends \Eden {

        const PEM = '/paypal/cacert.pem';

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function authorization($user, $password, $signature, $certificate = NULL) {
            Eden_Paypal_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string', 'null');
            if (!is_string($certificate)) {
                $certificate = dirname(__FILE__) . self::PEM;
            }return Eden_Paypal_Authorization::i($user, $password, $signature, $certificate);
        }

        public function billing($user, $password, $signature, $certificate = NULL) {
            if (!is_string($certificate)) {
                $certificate = dirname(__FILE__) . self::PEM;
            }return Eden_Paypal_Billing::i($user, $password, $signature, $certificate);
        }

        public function button($user, $password, $signature, $certificate = NULL) {
            Eden_Paypal_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string', 'null');
            if (!is_string($certificate)) {
                $certificate = dirname(__FILE__) . self::PEM;
            }return Eden_Paypal_Button::i($user, $password, $signature, $certificate);
        }

        public function checkout($user, $password, $signature, $certificate = NULL, $live = false) {
            Eden_Paypal_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string', 'null');
            if (!is_string($certificate)) {
                $certificate = dirname(__FILE__) . self::PEM;
            }return Eden_Paypal_Checkout::i($user, $password, $signature, $certificate, $live);
        }

        public function direct($user, $password, $signature, $certificate = NULL) {
            Eden_Paypal_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string', 'null');
            if (!is_string($certificate)) {
                $certificate = dirname(__FILE__) . self::PEM;
            }return Eden_Paypal_Direct::i($user, $password, $signature, $certificate);
        }

        public function recurring($user, $password, $signature, $certificate = NULL) {
            Eden_Paypal_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string', 'null');
            if (!is_string($certificate)) {
                $certificate = dirname(__FILE__) . self::PEM;
            }return Eden_Paypal_Recurring::i($user, $password, $signature, $certificate);
        }

        public function transaction($user, $password, $signature, $certificate = NULL) {
            Eden_Paypal_Error::i()->argument(1, 'string')->argument(2, 'string')->argument(3, 'string')->argument(4, 'string', 'null');
            if (!is_string($certificate)) {
                $certificate = dirname(__FILE__) . self::PEM;
            }return Eden_Paypal_Transaction::i($user, $password, $signature, $certificate);
        }

    }

}
/* Eden_Xend_Error */
if (!class_exists('Eden_Xend_Error')) {

    class Eden_Xend_Error extends Eden_Error {

        public static function i($message = NULL, $code = 0) {
            $class = __CLASS__;
            return new $class($message, $code);
        }

    }

}
/* Eden_Xend_Base */
if (!class_exists('Eden_Xend_Base')) {

    class Eden_Xend_Base extends \Eden {

        const SHIPMENT_WSDL = 'https://www.xend.com.ph/api/ShipmentService.asmx?wsdl';
        const TRACKING_WSDL = 'https://www.xend.com.ph/api/TrackingService.asmx?wsdl';
        const RATE_WSDL = 'https://www.xend.com.ph/api/RateService.asmx?wsdl';
        const BOOKING_WSDL = 'https://xend.com.ph/api/BookingService.asmx?wsdl';
        const HEADER = 'https://www.xend.com.ph/api/';
        const WAY_BILL_NO = 'WaybillNo';
        const USER_TOKEN = 'UserToken';
        const AUTH_HEADER = 'AuthHeader';
        const LENGTH = 'DimensionL';
        const WIDTH = 'DimensionW';
        const HEIGHT = 'DimensionH';
        const VALUE = 'DeclaredValue';
        const TEST_SHIPMENT_WSDL = 'https://www.xend.com.ph/apitest/ShipmentService.asmx?wsdl';
        const TEST_BOOKING_WSDL = 'https://xend.com.ph/apitest/BookingService.asmx?wsdl';
        const TEST_HEADER = 'https://www.xend.com.ph/apitest/';
        const METRO_MANILA_EXPRESS = 'MetroManilaExpress';
        const PROVINCIAL_EXPRESS = 'ProvincialExpress';
        const INTERNATIONAL_POSTAL = 'InternationalPostal';
        const INTERNATIONAL_EMS = 'InternationalEMS';
        const INTERNATIONAL_EXPRESS = 'InternationalExpress';
        const RIZAL_METRO_MANILA_EXPRESS = 'RizalMetroManilaExpress';
        const DOCUMENT = 'Document';
        const PARCEL = 'Parcel';
        const BOOKING_DATE = 'BookingDate';
        const REFERENCE_NUMBER = 'AddressRefNo';
        const REMARKS = 'Remarks';
        const WEIGHT = 'Weight';
        const DESTINATION_VALUE = 'DestinationValue';
        const INSURANCE = 'AddInsurance';

        protected $_userToken = NULL;
        protected $_test = NULL;

        public function __construct($userToken, $test = true) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_userToken = $userToken;
            $this->_test = $test;
        }

    }

}
/* Eden_Xend_Booking */
if (!class_exists('Eden_Xend_Booking')) {

    class Eden_Xend_Booking extends Eden_Xend_Base {

        const FIRST_NAME = 'FirstName';
        const LAST_NAME = 'LastName';
        const STREET1 = 'Street1';
        const STREET2 = 'Street2';
        const CITY = 'City';
        const PROVINCE = 'Province';
        const POSTAL_CODE = 'PostalCode';
        const LANDMARK = 'Landmark';

        protected $_url = self::BOOKING_WSDL;
        protected $_header = self::HEADER;
        protected $_exceptionFlag = false;
        protected $_date = NULL;
        protected $_addressRefNo = NULL;
        protected $_remarks = NULL;
        protected $_firstName = NULL;
        protected $_lastName = NULL;
        protected $_street1 = NULL;
        protected $_street2 = NULL;
        protected $_city = NULL;
        protected $_province = NULL;
        protected $_postalCode = NULL;
        protected $_landmark = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getDetail() {
            if ($this->_test) {
                $this->_url = self::TEST_BOOKING_WSDL;
                $this->_header = self::TEST_HEADER;
            }$client = new SoapClient($this->_url, array());
            $funcs = $client->__getFunctions();
            $headerbody = array(self::USER_TOKEN => $this->_userToken);
            $header = new SoapHeader($this->_header, self::AUTH_HEADER, $headerbody);
            $client->__setSoapHeaders($header);
            try {
                $result = $client->GetAddress();
            } catch (SoapFault $soapfault) {
                $this->_exceptionFlag = true;
                $exception = $soapfault->getMessage();
                preg_match_all('/: (.*?).at/s', $exception, $error, PREG_SET_ORDER);
                return $error[0][1];
            }return $result->GetAddressResult->Address;
        }

        public function getResponse() {
            $client = new SoapClient($this->_url, array());
            $funcs = $client->__getFunctions();
            $headerbody = array(self::USER_TOKEN => $this->_userToken);
            $header = new SoapHeader($this->_header, self::AUTH_HEADER, $headerbody);
            $client->__setSoapHeaders($header);
            $param = array(self::BOOKING_DATE => $this->_date, self::REFERENCE_NUMBER => $this->_addressRefNo, self::REMARKS => $this->_remarks);
            try {
                $result = $client->Schedule($param);
            } catch (SoapFault $soapfault) {
                $this->_exceptionFlag = true;
                $exception = $soapfault->getMessage();
                preg_match_all('/: (.*?).at/s', $exception, $error, PREG_SET_ORDER);
                return $error[0][1];
            }return $result;
        }

        public function getSpecific() {
            $client = new SoapClient($this->_url, array());
            $funcs = $client->__getFunctions();
            $headerbody = array(self::USER_TOKEN => $this->_userToken);
            $header = new SoapHeader($this->_header, self::AUTH_HEADER, $headerbody);
            $client->__setSoapHeaders($header);
            $param = array(self::BOOKING_DATE => $this->_date, self::REMARKS => $this->_remarks, self::FIRST_NAME => $this->_firstName, self::LAST_NAME => $this->_lastName, self::STREET1 => $this->_street1, self::STREET2 => $this->_street2, self::CITY => $this->_city, self::PROVINCE => $this->_province, self::POSTAL_CODE => $this->_postalCode, self::LANDMARK => $this->_landmark);
            try {
                $result = $client->ScheduleDev($param);
            } catch (SoapFault $soapfault) {
                $this->_exceptionFlag = true;
                $exception = $soapfault->getMessage();
                preg_match_all('/: (.*?).at/s', $exception, $error, PREG_SET_ORDER);
                return $error[0][1];
            }return $result;
        }

        public function setAddressNumber($addressNumber) {
            Eden_Xend_Error::i()->argument(1, 'int');
            $this->_addressRefNo = $addressNumber;
            return $this;
        }

        public function setCity($city) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_city = $city;
            return $this;
        }

        public function setDate($date) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $start = strtotime($date);
            $this->_date = date('Y-m-d\TH\:i\:s\.u', $start);
            return $this;
        }

        public function setFirstName($firstName) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_firstName = $firstName;
            return $this;
        }

        public function setLandmark($landmark) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_landmark = $landmark;
            return $this;
        }

        public function setLastName($lastName) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_lastName = $lastName;
            return $this;
        }

        public function setPostalCode($postalCode) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_postalCode = $postalCode;
            return $this;
        }

        public function setProvince($province) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_province = $province;
            return $this;
        }

        public function setRemarks($remarks) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_remarks = $remarks;
            return $this;
        }

        public function setStreet1($street1) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_street1 = $street1;
            return $this;
        }

        public function setStreet2($street2) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_street2 = $street2;
            return $this;
        }

    }

}
/* Eden_Xend_Rate */
if (!class_exists('Eden_Xend_Rate')) {

    class Eden_Xend_Rate extends Eden_Xend_Base {

        const SERVICE_TYPE = 'ServiceTypeValue';
        const SHIPMENT_TYPE = 'ShipmentTypeValue';

        protected $_exceptionFlag = false;
        protected $_serviceType = NULL;
        protected $_shipmentType = NULL;
        protected $_weight = NULL;
        protected $_lenght = NULL;
        protected $_width = NULL;
        protected $_height = NULL;
        protected $_declaredValue = NULL;
        protected $_destinationValue = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getResponse() {
            $client = new SoapClient(self::RATE_WSDL);
            $funcs = $client->__getFunctions();
            $headerbody = array(self::USER_TOKEN => $this->_userToken);
            $header = new SoapHeader(self::HEADER, self::AUTH_HEADER, $headerbody);
            $client->__setSoapHeaders($header);
            $query = array(self::SERVICE_TYPE => $this->_serviceType, self::SHIPMENT_TYPE => $this->_shipmentType, self::DESTINATION_VALUE => $this->_destinationValue, self::WEIGHT => $this->_weight, self::LENGTH => $this->_length, self::WIDTH => $this->_width, self::HEIGHT => $this->_height, self::VALUE => $this->_declaredValue, self::INSURANCE => true);
            try {
                $result = $client->Calculate($query);
            } catch (SoapFault $soapfault) {
                $this->_exceptionFlag = true;
                $exception = $soapfault->getMessage();
                preg_match_all('/: (.*?).at/s', $exception, $error, PREG_SET_ORDER);
                return $error[0][1];
            }return $result->CalculateResult;
        }

        public function setDeclaredValue($declaredValue) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_declaredValue = $declaredValue;
            return $this;
        }

        public function setDestinationValue($destinationValue) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_destinationValue = $destinationValue;
            return $this;
        }

        public function setDocument() {
            $this->_shipmentType = self::DOCUMENT;
            return $this;
        }

        public function setHeight($height) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_height = $height;
            return $this;
        }

        public function setInternationalEms() {
            $this->_serviceType = self::INTERNATIONAL_EMS;
            return $this;
        }

        public function setInternationalExpress() {
            $this->_serviceType = self::INTERNATIONAL_EXPRESS;
            return $this;
        }

        public function setInternationalPostal() {
            $this->_serviceType = self::INTERNATIONAL_POSTAL;
            return $this;
        }

        public function setLenght($length) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_length = $length;
            return $this;
        }

        public function setMetroManilaExpress() {
            $this->_serviceType = self::METRO_MANILA_EXPRESS;
            return $this;
        }

        public function setParcel() {
            $this->_shipmentType = self::PARCEL;
            return $this;
        }

        public function setProvincialExpress() {
            $this->_serviceType = self::PROVINCIAL_EXPRESS;
            return $this;
        }

        public function setRizalMetroManilaExpress() {
            $this->_serviceType = self::RIZAL_METRO_MANILA_EXPRESS;
            return $this;
        }

        public function setWeight($weight) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_weight = $weight;
            return $this;
        }

        public function setWidth($width) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_width = $width;
            return $this;
        }

    }

}
/* Eden_Xend_Shipment */
if (!class_exists('Eden_Xend_Shipment')) {

    class Eden_Xend_Shipment extends Eden_Xend_Base {

        const SHIPMENT = 'shipment';
        const SERVICE_TYPE = 'ServiceTypeValue';
        const SHIPMENT_TYPE = 'ShipmentTypeValue';
        const PURPOSE = 'PurposeOfExportValue';
        const NAME = 'RecipientName';
        const COMPANY = 'RecipientCompanyName';
        const ADDRESS1 = 'RecipientAddress1';
        const ADDRESS2 = 'RecipientAddress2';
        const CITY = 'RecipientCity';
        const PROVINCE = 'RecipientProvince';
        const COUNTRY = 'RecipientCountry';
        const INSURED = 'IsInsured';
        const INSTRUCTION = 'SpecialInstructions';
        const DESCRIPTION = 'Description';
        const CLIENT = 'ClientReference';
        const DATE_CREATED = 'DateCreated';
        const DATE_PRINTED = 'DatePrinted';
        const POSTAL_CODE = 'RecipientPostalCode';
        const PHONE_NUMBER = 'RecipientPhoneNo';
        const EMAIL = 'RecipientEmailAddress';
        const MANUFACTURED = 'CountryManufactured';
        const SHIPPING_FEE = 'ShippingFee';
        const INSURANCE_FEE = 'InsuranceFee';

        protected $_test = true;
        protected $_exceptionFlag = false;
        protected $_url = self::SHIPMENT_WSDL;
        protected $_header = self::HEADER;
        protected $_wayBillNo = NULL;
        protected $_serviceType = NULL;
        protected $_shipmentType = NULL;
        protected $_purpose = NULL;
        protected $_weight = NULL;
        protected $_length = NULL;
        protected $_width = NULL;
        protected $_height = NULL;
        protected $_declaredValue = NULL;
        protected $_name = NULL;
        protected $_address1 = NULL;
        protected $_address2 = NULL;
        protected $_city = NULL;
        protected $_provice = NULL;
        protected $_country = NULL;
        protected $_specialInstruction = NULL;
        protected $_description = NULL;
        protected $_company = NULL;
        protected $_shippingFee = NULL;
        protected $_postalCode = NULL;
        protected $_phoneNumber = NULL;
        protected $_email = NULL;
        protected $_wayBill = NULL;
        protected $_fee = 0;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getDetail() {
            $exceptionFlag = false;
            $client = new SoapClient($this->_url, array());
            $funcs = $client->__getFunctions();
            $headerbody = array(self::USER_TOKEN => $this->_userToken);
            $header = new SoapHeader($this->_header, self::AUTH_HEADER, $headerbody);
            $client->__setSoapHeaders($header);
            try {
                $result = $client->Get(array(self::WAY_BILL_NO => $this->_wayBill));
            } catch (SoapFault $soapfault) {
                $this->_exceptionFlag = true;
                $exception = $soapfault->getMessage();
                preg_match_all('/: (.*?).at/s', $exception, $error, PREG_SET_ORDER);
                return $error[0][1];
            }return $result->GetResult;
        }

        public function getResponse() {
            $client = new SoapClient($this->_url, array());
            $funcs = $client->__getFunctions();
            $headerbody = array(self::USER_TOKEN => $this->_userToken);
            $header = new SoapHeader($this->_header, self::AUTH_HEADER, $headerbody);
            $client->__setSoapHeaders($header);
            $query = array(self::SERVICE_TYPE => $this->_serviceType, self::SHIPMENT_TYPE => $this->_shipmentType, self::PURPOSE => $this->_purpose, self::WEIGHT => $this->_weight, self::LENGTH => $this->_length, self::WIDTH => $this->_width, self::HEIGHT => $this->_height, self::VALUE => $this->_declaredValue, self::NAME => $this->_name, self::COMPANY => $this->_company, self::ADDRESS1 => $this->_address1, self::ADDRESS2 => $this->_address2, self::CITY => $this->_city, self::PROVINCE => $this->_provice, self::COUNTRY => $this->_country, self::INSURED => TRUE, self::INSTRUCTION => $this->_specialInstruction, self::DESCRIPTION => $this->_description, self::CLIENT => '', self::MANUFACTURED => '', self::POSTAL_CODE => $this->_postalCode, self::PHONE_NUMBER => $this->_phoneNumber, self::EMAIL => $this->_email, self::DATE_CREATED => time(), self::DATE_PRINTED => time(), self::SHIPPING_FEE => $this->_fee, self::INSURANCE_FEE => '1');
            try {
                $result = $client->Create(array(self::SHIPMENT => $query));
            } catch (SoapFault $soapfault) {
                $this->_exceptionFlag = true;
                $exception = $soapfault->getMessage();
                preg_match_all('/: (.*?).at/s', $exception, $error, PREG_SET_ORDER);
                return $error[0][1];
            }$this->_wayBill = $result->CreateResult;
            return $this->getDetail();
        }

        public function setAddress1($address1) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_address1 = $address1;
            return $this;
        }

        public function setAddress2($address2) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_address1 = $address2;
            return $this;
        }

        public function setCity($city) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_city = $city;
            return $this;
        }

        public function setCompany($company) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_company = $company;
            return $this;
        }

        public function setCountry($country) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_country = $country;
            return $this;
        }

        public function setDeclaredValue($declaredValue) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_declaredValue = $declaredValue;
            return $this;
        }

        public function setDescription($description) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_description = $description;
            return $this;
        }

        public function setDocument() {
            $this->_shipmentType = self::DOCUMENT;
            return $this;
        }

        public function setEmail($email) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_email = $email;
            return $this;
        }

        public function setHeight($height) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_height = $height;
            return $this;
        }

        public function setInternationalEMS() {
            $this->_serviceType = self::INTERNATIONAL_EMS;
            return $this;
        }

        public function setInternationalExpress() {
            $this->_serviceType = self::INTERNATIONAL_EXPRESS;
            return $this;
        }

        public function setInternationalPostal() {
            $this->_serviceType = self::INTERNATIONAL_POSTAL;
            return $this;
        }

        public function setLength($length) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_length = $length;
            return $this;
        }

        public function setMetroManilaExpress() {
            $this->_serviceType = self::METRO_MANILA_EXPRESS;
            return $this;
        }

        public function setName($name) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_name = $name;
            return $this;
        }

        public function setParcel() {
            $this->_shipmentType = self::PARCEL;
            return $this;
        }

        public function setPhoneNumber($phoneNumber) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_phoneNumber = $phoneNumber;
            return $this;
        }

        public function setPostalCode($postalCode) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_postalCode = $postalCode;
            return $this;
        }

        public function setProvince($province) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->province = $province;
            return $this;
        }

        public function setProvincialExpress() {
            $this->_serviceType = self::PROVINCIAL_EXPRESS;
            return $this;
        }

        public function setPurpose($purpose) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_purpose = $purpose;
            return $this;
        }

        public function setRizalMetroManilaExpress() {
            $this->_serviceType = self::RIZAL_METRO_MANILA_EXPRESS;
            return $this;
        }

        public function setShippingFee($fee) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_fee = $fee;
            return $this;
        }

        public function setSpecialInstruction($specialInstruction) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_specialInstruction = $specialInstruction;
            return $this;
        }

        public function setWayBillNumber($wayBillNo) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_wayBillNo = $wayBillNo;
            return $this;
        }

        public function setWeight($weight) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_weight = $weight;
            return $this;
        }

        public function setWidth($width) {
            Eden_Xend_Error::i()->argument(1, 'int', 'float');
            $this->_width = $width;
            return $this;
        }

    }

}
/* Eden_Xend_Tracking */
if (!class_exists('Eden_Xend_Tracking')) {

    class Eden_Xend_Tracking extends Eden_Xend_Base {

        protected $_exceptionFlag = false;
        protected $_wayBillNo = NULL;

        public static function i() {
            return self::_getMultiple(__CLASS__);
        }

        public function getTracking() {
            $client = new SoapClient(self::TRACKING_WSDL, array());
            $funcs = $client->__getFunctions();
            $headerbody = array(self::USER_TOKEN => $this->_userToken);
            $header = new SoapHeader(self::HEADER, self::AUTH_HEADER, $headerbody);
            $client->__setSoapHeaders($header);
            $query = array(self::WAY_BILL_NO => $this->_wayBillNo);
            try {
                $result = $client->GetList($query);
            } catch (SoapFault $soapfault) {
                $this->_exceptionFlag = true;
                $exception = $soapfault->getMessage();
                preg_match_all('/: (.*?).at/s', $exception, $error, PREG_SET_ORDER);
                return $error[0][1];
            }return $result;
        }

        public function setWayBillNumber($wayBillNumber) {
            Eden_Xend_Error::i()->argument(1, 'string');
            $this->_wayBillNo = $wayBillNumber;
            return $this;
        }

    }

}
/* Eden_Xend */
if (!class_exists('Eden_Xend')) {

    class Eden_Xend extends \Eden {

        public static function i() {
            return self::_getSingleton(__CLASS__);
        }

        public function booking($userToken, $test = true) {
            return Eden_Xend_Booking::i($userToken, $test = true);
        }

        public function rate($userToken, $test = true) {
            return Eden_Xend_Rate::i($userToken, $test = true);
        }

        public function shipment($userToken, $test = true) {
            return Eden_Xend_Shipment::i($userToken, $test = true);
        }

        public function tracking($userToken, $test = true) {
            return Eden_Xend_Tracking::i($userToken, $test = true);
        }

    }

}
