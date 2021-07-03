<?php

namespace App\Http\Controllers\Api;

use App\Models\user;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Traits\ApiResponse;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use Auth;
use Symfony\Component\HttpFoundation\Response as Response;
use Illuminate\Http\Exceptions\HttpResponseException;

class AuthController extends Controller
{
    Use ApiResponse;
    public function register(RegisterRequest $request)
    {
    	$validated = $request->validated();
    	$user = User::create([
    		'name'=>$validated['name'],
    		'email'=>$validated['email'],
    		'password'=>bcrypt($validated['password']),
    	]);

    	$token = $user->createToken('auth_token')->plainTextToken;
    	return $this->apiSuccess([
    		'token'=>$token,
    		'token_type'=>'Bearer',
    		'user'=>$user,
    	]);
    }

    public function login(LoginRequest $request)
    {
    	$validated = $request->validated();
    	if(!Auth::attempt($validated))
    	{
    		return $this->apiError('Credential not match',Response::HTTP_UNAUTHORIZED);
    	}

    	$user = User::where('email',$validated['email'])->first();
    	$token = $user->createToken('auth_token')->plainTextToken;

    	return $this->apiSuccess([
    		'token'=>$token,
    		'token_type'=>'Bearer',
    		'user'=>$user,
    	]);
    }
    
    public function logout()
    {
    	try
    	{
    		Auth::user()->tokens->each(function($token, $key) {
		        $token->delete();
		    });
    		return $this->apiSuccess('Token revoked');
    	}catch(\Throwable $e)
    	{
    		 throw new HttpResponseException($this->apiError(
             null,
             Response::HTTP_INTERNAL_SERVER_ERROR,
        	));
    	}
    }
}
