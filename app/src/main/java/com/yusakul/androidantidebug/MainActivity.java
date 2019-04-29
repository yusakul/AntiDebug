package com.yusakul.androidantidebug;

import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import java.util.TimerTask;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private static final int TIMER = 50000; //5s
    private MyTimeTask task;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        AntiDebug();

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public native void antidebug01();
    public native void antidebug02();
    public native void antidebug03();
    public native void antidebug04();
    public native void antidebug05();
    public native void antidebug06();
    public native void antidebug07();

    public void AntiDebug()
    {
        //反调试01
        new Thread() {
            @Override
            public void run() {
                setTimer();
            }
        }.start();

    }

    private void setTimer(){
        task =new MyTimeTask(1000, new TimerTask() {
            @Override
            public void run() {
                mHandler.sendEmptyMessage(TIMER);
                //或者发广播，启动服务都是可以的

            }
        });
        task.start();
    }

    private Handler mHandler = new Handler(){
        @Override
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            switch (msg.what){
                case TIMER: {
                    //在此执行定时操作
                    antidebug01();
                    antidebug02();
                    antidebug03();
                    antidebug04();
                   // antidebug05();
                    //antidebug06();
                    antidebug07();
                    break;
                }
                default:
                    break;
            }
        }
    };


    private void stopTimer(){
        task.stop();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopTimer();
    }
}
