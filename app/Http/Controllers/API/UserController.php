<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Facade\FlareClient\Http\Response;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

use function PHPUnit\Framework\returnSelf;

class UserController extends Controller
{
    public function register(Request $request){
        try{
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255','unique:users'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'phone' => ['nullable', 'string', 'max:255'],
                'password' => ['required', 'string', new Password]
            ]);//request validate
            User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->password)
            ]);//user create

            $user = User::where('email', $request->email)->first();

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type'=>'Bearer',
                'user'=> $user
            ], 'User Registered');
        }catch(Exception $error){
            return ResponseFormatter::error([
                'message'=> 'Something went wrong',
                'error' => $error
            ],  'Authentication Failed', 500);
        }
    }

    public function login(Request $request){
        try{
            $request->validate([
                'email' => 'email|required',
                'password' => 'required'
            ]);

            $credentials = request(['email', 'password']);
            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message'=> 'Unauthorized'
                ], 'Authentication Failed', 500);
            }

            $user = User::where('email', $request->email)->first();

            if(!Hash::check($request->password, $user->password, [])){
                throw new \Exception('Invalid Credentials');
            }

            $tokenResult = $user-> createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token'=>$tokenResult,
                'token_type'=>'Bearer',
                'user'=>$user
            ], 'Authenticated');
        }catch(Exception $error){
            return ResponseFormatter::error([
                'message'=>'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
            //
        }
    }

    public function fetch(Request $request){
        return ResponseFormatter::success($request->user(), 'Data profile user berhasil diambil');
    }

    public function updateProfile(Request $request){
        
       try{
            $data = $request->all();
            $request->validate([
                'nama'=>['nullable', 'string', 'max:255'],
                'email'=>['nullable','string', 'max:255', 'unique:users'],
                'username'=>['nullable', 'string', 'max:255'],
                'phone'=>['nullable', 'string', 'max:255']
            ]);

            $user = Auth::user();
            $user->update($data);
            return ResponseFormatter::success($user, 'Profile Updated');

       }catch(Exception $error){
            return ResponseFormatter::error([
                'message'=>'Something went wrong',
                'error' => $error
            ], 'Update Failed', 500);
            //
       } 
       
    }

    public function logout(Request $request){
        $token = $request->user()->currentAccessToken()->delete();

        return ResponseFormatter::success($token, 'Token Revoked');
    }
}
