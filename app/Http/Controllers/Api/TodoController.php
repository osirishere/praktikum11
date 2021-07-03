<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Todo;
use App\Traits\ApiResponse;
use Illuminate\Http\Request;
use App\Http\Requests\TodoRequest;
use Auth;

class TodoController extends Controller
{
    use ApiResponse;
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $user = Auth::user();
        $todos = Todo::with('user')
                ->where('user_id',$user->id)
                ->get();
        return $this->apiSuccess([
            'todo'=>$todos,
        ]);
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(TodoRequest $request)
    {
        $request->validated();
        $user = Auth::user();
        $todo = new Todo($request->all());
        $todo->user()->associate($user);
        $todo->save();

        //return $this->apiSucess($todo->load('user'));
        return $this->apiSuccess([
            'todo'=>$todo->load('user'),
        ]);
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\Todo  $todo
     * @return \Illuminate\Http\Response
     */
    public function show(Todo $todo)
    {
        return $this->apiSucess($todo->load('user'));
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\Todo  $todo
     * @return \Illuminate\Http\Response
     */
    public function update(TodoRequest $request,$id)
    {
        $request->validated();
        $todo = Todo::find($id);
        $tod->todo = $request->todo;
        $todo->label = $request->label;
        $todo->done = $request->done;
        $todo->save();
        return $this->apiSuccess([
                'todo'=>'Sucess diupdate',
                'data'=>$todo,
            ]);
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\Todo  $todo
     * @return \Illuminate\Http\Response
     */
    public function destroy($todo)
    {
        $arr = Todo::find($todo);
        if(Auth::user()->id==$arr->user_id)
        {
            $arr->delete();
               return $this->apiSuccess([
                'todo'=>'Sucess dihapus',
            ]);
        }
        return $this->apiError(
            'Unauthorized',
            Response::HTTP_UNAUTHORIZED
        );
    }
}
