<?php

namespace App\Http\Controllers\Api\User;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\User\LoginRequest;
use App\Http\Resources\User\AuthResource;
use App\Http\Requests\User\RegisterRequest;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function login(LoginRequest $request){
        // return $request;

        $user = User::where('phone', $request->phone)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {

            throw ValidationException::withMessages([
                'phone' => ['The provided credentials are incorrect.'],
            ]);
        }

        $token = $user->createToken('token')->plainTextToken;
        // return AuthResource::make($user);
        return (new AuthResource($user))
                ->additional(['meta' => [
                    'token' => $token
                ]]);
    }

    public function registration(RegisterRequest $request){
        // return $request->all();
        $user = new User;

        $user->name = $request->name;
        $user->email = $request->email;
        $user->phone = $request->phone;
        $user->password = Hash::make($request->password);
        $user->save();

        $token = $user->createToken('token')->plainTextToken;
        return (new AuthResource($user))
        ->additional(['meta' => [
            'token' => $token
        ]]);
    }

    public function logout(Request $request){
        $request->user()->tokens()->delete();

        return response()->json([
            'msg'=>"Logout success",
            'code'=>200,
            'status'=>true
        ]);
    }

    public function users(){
        return User::get();
    }
}
