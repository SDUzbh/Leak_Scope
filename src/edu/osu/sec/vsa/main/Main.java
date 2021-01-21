package edu.osu.sec.vsa.main;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipException;

import org.json.JSONObject;

import soot.Scene;
import soot.options.Options;
import brut.androlib.AndrolibException;
import edu.osu.sec.vsa.base.GlobalStatistics;
import edu.osu.sec.vsa.graph.CallGraph;
import edu.osu.sec.vsa.graph.DGraph;
import edu.osu.sec.vsa.graph.IDGNode;
import edu.osu.sec.vsa.graph.ValuePoint;
import edu.osu.sec.vsa.utility.ErrorHandler;
import edu.osu.sec.vsa.utility.FileUtility;
import edu.osu.sec.vsa.utility.Logger;

public class Main {

	static JSONObject targetMethds;	//目标方法

	public static void startWatcher(int sec) {
		Thread t = new Thread() {
			public void run() {
				try {
					Thread.sleep(sec * 1000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Logger.printE("TimeOut,exiting...");
				//System.exit(0);
			}
		};
		t.setDaemon(true);
		t.start();
	}

	public static void main(String[] args) throws ZipException, IOException, AndrolibException {
		initDirs();//新建output，log文件。

		Config.ANDROID_JAR_DIR = args[0];
		
		targetMethds = new JSONObject(new String(Files.readAllBytes(Paths.get(args[1]))));//读取json文件的信息,转换为json格式
		String apk = targetMethds.getString("apk");//获取目标apk
		
		Thread.setDefaultUncaughtExceptionHandler(new ErrorHandler(args[0]));//设置异常处理

		long stime = System.currentTimeMillis();//start time

		ApkContext apkcontext = ApkContext.getInstance(apk);//创建apkContext对象，path成员初始化
		Logger.TAG = apkcontext.getPackageName();

		soot.G.reset();		//G is a class to group together all the global variables in Soot.
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_process_dir(Collections.singletonList(apkcontext.getAbsolutePath()));
		Options.v().set_android_jars(Config.ANDROID_JAR_DIR);
		Options.v().set_force_android_jar(Config.ANDROID_JAR_DIR);
		Options.v().set_process_multiple_dex(true);

		Options.v().set_whole_program(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_output_format(Options.output_format_none);

		Options.v().ignore_resolution_errors();
		Scene.v().loadNecessaryClasses();		//加载所有用到的类
		

		//startWatcher(Config.TIMEOUT);
		CallGraph.init();						//生成函数调用图
		//startWatcher(20);
		long itime = System.currentTimeMillis();

		DGraph dg = new DGraph();//生成D图

		List<ValuePoint> allvps = new ArrayList<ValuePoint>();
		List<ValuePoint> vps;
		String tsig;
		List<Integer> regIndex;
		JSONObject tmp;


		for (Object jobj : targetMethds.getJSONArray("methods")) {
			
			tmp = (JSONObject) jobj;
			
			tsig = tmp.getString("method");//遍历输入json文件的method的三字节码
			regIndex = new ArrayList<Integer>();

			for(Object tob:tmp.getJSONArray("parmIndexs")){//获得参数索引
				regIndex.add((Integer) tob);
			}

			vps = ValuePoint.find(dg, tsig, regIndex);		//处理签名的函数
			for (ValuePoint vp : vps) {
				//System.out.println(vp);
				//System.out.println("sigatureInApp"+tsig);
				//tmp = new JSONObject();
				//tmp.put("sigatureInApp", tsig);
				//tmp.put("sigatureIndex", targetMethds.getString(tsig));
				vp.setAppendix(tmp);

				vp.print();
			}
			allvps.addAll(vps);
		}
		dg.solve(allvps);
		long etime = System.currentTimeMillis();

		JSONObject result = new JSONObject();

		for (IDGNode tn : dg.getNodes()) {
			//Logger.print(tn.toString());//打印Dgragh中各个节点的信息，包括类名，方法，语句，能否抵达，前驱，BackwardContexts
		}

		for (ValuePoint vp : allvps) {
			tmp = vp.toJson();
			if (tmp.has("ValueSet"))
				//Logger.print(tmp.getJSONArray("ValueSet").toString());
			result.append("ValuePoints", vp.toJson());
		}

		//result.put("pname", ApkContext.getInstance().getPackageName());
		//result.put("DGraph", dg.toJson());
		//result.put("initTime", (itime - stime));
		//result.put("solveTime", (etime - itime));
		//result.put("GlobalStatistics", GlobalStatistics.getInstance().toJson());	//GlobalStatistics

		wf(result.toString());//将JSONObjeact输出到目标文件
		
	}

	public static void wf(String content) {
		FileUtility.wf(Config.RESULTDIR + ApkContext.getInstance().getPackageName(), content, false);
	}

	public static void initDirs() {
		File tmp = new File(Config.RESULTDIR);//output file
		if (!tmp.exists())
			tmp.mkdir();
		tmp = new File(Config.LOGDIR);//log file
		if (!tmp.exists())
			tmp.mkdir();
	}
}
