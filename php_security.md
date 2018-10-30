# Security features of Laravel 5.
[omniceps.com](http://www.omniceps.com/security-features-laravel-application-security/)
## Authentication system
In the deep core Laravel uses **"providers"** and **"guards"** to facilitate authentication. With Guards one can control how users will be authenticated for each request made and the providers allow retrieving of users from the database.
The only part which remains unimplemented is setting up the database, controllers and user related models to complete the authentication.

## Protection against SQL injection
ORM in Laravel uses PDO parameter binding in order to fight against SQL injection. This type of binding the parameters ensures that the data passed from users in request variables are directly not utilized in SQL queries.

## Protection against CSRF (Cross Site Request Forgery)
Laravel uses CSRF tokens in order to restrict 3rd parties from generating such forged requests. This is done by generating and adding a valid token that should be added in each request whether its coming from a form or whether its an AJAX request. Laravel then compares this token automatically with the value which it has saved additionally to that particular user’s session. In case the token doesn’t match with the one stored that particular request is considered to be invalid, otherwise from CSRF point of view that request is valid.

Creating forms using standard HTML in blade templates, should be protected by passing the CSRF token in the form:
```html
<form name="test">
{!! csrf_field() !!}
<!-- Other inputs can come here-->
</form>
```
The recommended method of generating HTML by LaravelCollective/html takes care of CSRF token and adds it automatically for every form.

## Protecting against XSS (Cross Site Scripting)
Laravel does automatic escaping while saving content to database and also while printing out content in the HTML. So when a variable is rendered with escape it will be outputted on HTML as something like:
```html
&lt;script&gt;alert("You are hacked")&lt;/script&gt;
```

# Improving Laravel application security
Although Laravel comes with a lot of security features, which already makes it more secure than many of the PHP frameworks out there. But still you can improve Laravel application security by implementing the following items.

## Avoid using Raw Queries to prevent SQL injection
There are still instances where a developer would like to use a raw query instead of generating a query using Laravel's ORM. But while doing so one must use prepared statements.

**Bad code** :shit:

The statement **1=1** used in OR condition will result in returning all the rows in the users table.
```php
Route::get('this-is-prone-to-sql-injection',  function()  {
	$name  =  "'Simon Darmandieu' OR 1=1";
	return  DB::select(
		DB::raw("SELECT * FROM users WHERE name = $name")
	);
});
```
**Good code** :thumbsup:

When Laravel will replace the question marks with query variables, it will automatically escape the input variables.
```php
Route::get('safe-from-sql-injection',  function()  {
	$name  =  "'Simon Darmandieu' OR 1=1";
	return  DB::select(
		DB::raw("SELECT * FROM users WHERE name = ?",  [$name])
	);
});
```
## Force HTTPS if your application is exchanging sensitive information
Get an SSL certificate installed and use one of many Laravel's helpers to shift between HTTP and HTTPS and also hide certain routes. For example one can define the following filter which in turn will redirect users to a secured route:
```php
Route::filter('https',  function()  {
	if  (  !  Request::secure())
		return  Redirect::secure(URI::current());
});
```

## Escape content to prevent XSS
To avoid XSS attacks one should use the double brace syntax in the blade templates: **({{ $variable }})**

Only use **{!! $variable !!}** syntax when you are sure that the data in the variable is safer to be displayed.

## Setup Laravel security headers
Use https://github.com/BePsvPT/secure-headers for adding extra security headers to your Laravel app. This will include all the main headers.

## Use Laravel Purifier to enhance your security
For outputting some HTML variable to the client one can use HTML Purifier which will clean up the code and take care of illegal and missing HTML.

https://kuztek.com/blog/use-laravel-purifier-security