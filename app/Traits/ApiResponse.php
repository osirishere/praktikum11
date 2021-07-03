<?php 
namespace App\Traits;
trait ApiResponse
{
	protected function apiSuccess($data, $code=200,$message=null)
	{
		return response()->json([
			'data'=>$data,
			'message'=>$message,
		],$code);
	}

	protected function apiError($error, $code,$message=null)
	{
		return response()->json([
			'errors'=>$error,
			'message'=>$message,
		],$code);
	}
}