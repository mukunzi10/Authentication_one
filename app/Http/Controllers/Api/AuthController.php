<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\facades\Validator;
use Illuminate\Support\facades\Hash;
use Illuminate\Support\facades\Auth;
use App\Models\User;

class AuthController extends Controller
{
    // Return errors if validation error occur.
    public function register(Request $request){
        $validator=Validator::make($request->all(),[
            'name' => 'required|string|max:255',
        'email' => 'required|email|unique:users|max:255',
        'password' => 'required|min:4',
        ]);
        if($validator->fails()){
            $errors = $validator->errors();
            return response()->json([
                'error' => $errors
            ], 400);    

        }
         // Check if validation pass then create user and auth token. Return the auth token
         if($validator->passes()){
             $user=User::create([
                 'name'=>$request->name,
                 'email'=>$request->email,
                 'password'=>Hash::make($request->password)

             ]);

         }
         $token=$user->createToken('auth_token')->plainTextToken;
         return response()->json([
             'access_Token'=>$token,
             'Token_type'=>'Bearer']);



    }
    public function login(Request $request){
        if(!Auth::attempt($request->only('email','password'))){
            return response()->json([
                'message' => 'Invalid login details'
            ], 401);

        }
        $user = User::where('email', $request['email'])->firstOrFail();
    $token = $user->createToken('auth_token')->plainTextToken;
    return response()->json([
        'access_token' => $token,
        'token_type' => 'Bearer',
    ]);

    }
    public function me(Request $request)
{
    return $request->user();
}

}
