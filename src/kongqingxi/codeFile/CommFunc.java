package com.zjmobile.util;

import java.io.PrintWriter;
import java.io.StringWriter;

import static java.util.UUID.randomUUID;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import com.richinfo.kafka.KafkaTopicEnum;
import com.richinfo.kafka.SjyytKafkaProducer;
import com.zjmobile.data.*;
import com.zjmobile.enums.LogProcessEnum;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.sinovatech.rd.ordercenter.api.order.vo.OsOrderItemValueVo;
import com.sinovatech.rd.ordercenter.api.order.vo.OsOrderItemVo;
import com.sinovatech.rd.ordercenter.api.order.vo.OsOrderVo;
import com.zjmobile.Servlet.SpBottom;
import com.zjmobile.Servlet.broadband.QueryConOrderInfo;
import com.zjmobile.Servlet.broadband.bean.BroadbandComm;
import com.zjmobile.Servlet.broadband.ordercenter.OrderCenterUtil;
import com.zjmobile.Servlet.position.FirstPageAdvert;
import com.zjmobile.Servlet.user.LocationQuery;
import com.zjmobile.data.merge.UserRankFactory;
import com.zjmobile.enums.CacheEnum;
import com.zjmobile.enums.RedisCacheEnum;
import com.zjmobile.enums.RedisHome;
import com.zjmobile.enums.ResultEnum;
import org.logicalcobwebs.cglib.beans.BeanMap;
import scala.util.parsing.combinator.testing.Str;

public final class CommFunc implements GPRSSubjects {
	private static Random m_prng = new SecureRandom();
	private final static String CIPHER_ALGO = "AES/ECB/PKCS5Padding";
	public static final int SECONDS_IN_DAY = 60 * 60 * 24;
	public static final long MILLIS_IN_DAY = 1000L * SECONDS_IN_DAY;
	public static final Log loggin = LogFactory.getLog(CommFunc.class);
	public static final String[] encodes = {"GB2312","ISO-8859-1","UTF-8","GBK"};
	public static final String[] TIC_CODE_ARR = {Constant.TIC_GROUP_TYPE_CODE_50,Constant.TIC_GROUP_TYPE_CODE_100};
	public static final String st_ul_scid = "b2963a";// 手厅渠道触点编号
	public static final String IMEI = "RwIz01YccFFxBJbT";//imei为空时传
    public static final String diffLoginCheckUrl = "http://app-login.zj.chinamobile.com/zjlogin/";
	
	/**
	 * memcached缓存信息默认有效时间
	 */
    private final static Integer EXPIRE=24*60*60*1000;

	public static String normalizeUrl(String path, String url) {
		if (url == null || url.startsWith("http"))
			return url;
		StringBuilder rv = new StringBuilder(Config.getStr("app.zjweb"));
		if (!url.startsWith("/")) {
			rv.append(path);
		}
		rv.append(url);
		return rv.toString();
	}

	public static String safeAuthURL(String url,String num,String session) {
		String forword="";
		String nonce = getSafeNonce(16);
		String CIPHER_SECKEY = Config.getStr("privateKey.1001");
		String encinfo = encodeCommon(nonce, num, "", CIPHER_SECKEY);
		if(url==null){
			forword=url+"?cf=1001&nonce="+nonce+"&encpn="+encinfo+"&session="+session;
		}else{
			String[] urlz=url.split("\\?");
			forword=urlz[0]+"?cf=1001&nonce="+nonce+"&encpn="+encinfo+"&session="+session;
			if(urlz.length==2){
				forword=forword+"&"+urlz[1];
			}
		}
		return forword;
	}

	public static String sequenceId() {
		char[] buf = new char[24];
		int p = 0, i;

		long v = System.currentTimeMillis() & Long.MAX_VALUE;
		for (i = 0; i < 8; ++i) {
			int ch = (int) (v % 36);
			v /= 36;
			buf[7 - i] = (char) ((ch < 10) ? ('0' + ch) : ('A' + ch - 10));
			++p;
		}

		v = m_prng.nextLong() & Long.MAX_VALUE;
		for (i = 0; i < 8; ++i) {
			int ch = (int) (v % 36);
			v /= 36;
			buf[p] = (char) ((ch < 10) ? ('0' + ch) : ('A' + ch - 10));
			++p;
		}

		v = m_prng.nextLong() & Long.MAX_VALUE;
		for (i = 0; i < 8; ++i) {
			int ch = (int) (v % 36);
			v /= 36;
			buf[p] = (char) ((ch < 10) ? ('0' + ch) : ('A' + ch - 10));
			++p;
		}
		return new String(buf);

	}



	public static String randomId() {
		char[] buf = new char[24];
		int p = 0, i;

		long v = m_prng.nextLong() & Long.MAX_VALUE;
		for (i = 0; i < 12; ++i) {
			int ch = (int) (v % 36);
			v /= 36;
			buf[p] = (char) ((ch < 10) ? ('0' + ch) : ('A' + ch - 10));
			++p;
		}
		v = m_prng.nextLong() & Long.MAX_VALUE;
		for (i = 0; i < 12; ++i) {
			int ch = (int) (v % 36);
			v /= 36;
			buf[p] = (char) ((ch < 10) ? ('0' + ch) : ('A' + ch - 10));
			++p;
		}
		String token = new String(buf);
		String[] filter = { "select", "insert", "update", "delete","and","or","join", "union", "truncate", "drop", "alter", "alert",
				"confirm", "script", "prompt", "eval", "expression", "iframe"};
		for(String f:filter){
			if(token.toLowerCase().indexOf(f)>=0){
				return randomId();
			}
		}
		return token;
	}



	public static boolean pushSend(String pushId, String msg, int type)
			throws ZMCCInternalException {
		Map<String, Object> map = new TreeMap<String, Object>();

		map.put("appId", Config.getStr("push.appid"));
		map.put("msgTitle", "");
		map.put("msgBody", msg);
		map.put("ttl", 86400);
		map.put("msgType", type);
		map.put("tokenList", new String[] { pushId });
		JSONObject rv = JSONRequest.create(Config.getStr("push.url"), map)
				.execute();
		return rv.getIntValue("result") != 0;

	}

	private static final String[] CITY_NAMES = new String[] { "衢州", "杭州", "湖州",
			"嘉兴", "宁波", "绍兴", "台州", "温州", "丽水", "金华", "舟山" };

	public static String getCityName(int cityNum) {
		int i = cityNum - 570;
		if (i < 0 || i >= CITY_NAMES.length)
			return null;
		else
			return CITY_NAMES[i];
	}

	/**
	 * 用户类型判断
	 * @param num
	 * @return
	 */
	public static boolean is4G(Long num) {
		boolean tag=true;
		Account acc = AccountUtil.getAccountInfo(String.valueOf(num));
		if(acc!=null){
			if("0".equals(acc.getUsertype())){
				return false;
			}
		}
		return tag;
	}

	public static String getSafeNonce(int length) {
		// return false;
		char[] ss = new char[length];
		int i = 0;
		while (i < length) {
			int f = (int) (Math.random() * 3);
			if (f == 0)
				ss[i] = (char) ('A' + Math.random() * 26);
			else if (f == 1)
				ss[i] = (char) ('a' + Math.random() * 26);
			else
				ss[i] = (char) ('0' + Math.random() * 10);
			i++;
		}
		String is = new String(ss);
		return is;
	}

	public static String encodeCommon(String nonce,String num,String market_id,String CIPHER_SECKEY){
		String encinfo = "";
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(CIPHER_SECKEY.getBytes());
			md.update(nonce.getBytes());
			SecretKeySpec seckey = new SecretKeySpec(md.digest(), "AES");
			Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
			cipher.init(Cipher.ENCRYPT_MODE, seckey);
			encinfo = Hex.encodeHexString(cipher.doFinal((num+","+market_id).getBytes()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encinfo;
	}

	public static String getCurrMon(){
		DateFormat df=new SimpleDateFormat("yyyyMM");
		return df.format(new Date());
	}

	public static String getLastMon(){
		Calendar c = Calendar.getInstance();
		c.add(Calendar.MONTH, -1);
		DateFormat df=new SimpleDateFormat("yyyyMM");
		return df.format(c.getTime());
	}
	public static String getLastDate(){
		Calendar c = Calendar.getInstance();
		c.add(Calendar.MONTH, -1);
		DateFormat df=new SimpleDateFormat("yyyyMMdd");
		return df.format(c.getTime());
	}
	public static String getCurrDate(){
		Calendar c = Calendar.getInstance();
		DateFormat df=new SimpleDateFormat("yyyyMMdd");
		return df.format(c.getTime());
	}

	public static String getCurrTabName(String tableName){
		return tableName+"_"+getCurrMon();
	}

	public static String getCurrDateTabName(String tableName){
		return tableName+"_"+getCurrDate();
	}

	public static String getLastTabName(String tableName){
		return tableName+"_"+getLastMon();
	}

	

	/**
	 * 判断是否是数字
	 * @param str
	 * @return
	 */
	public static boolean isNumeric(String str) {
		for (int i = str.length(); --i >= 0;) {
			if (!Character.isDigit(str.charAt(i))) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 判断版本号大小
	 * @param str
	 * @return
	 */
	public static int compare(String s1, String s2) {
		if ((s1 == null||s1.trim().equals("")) && (s2 == null||s2.trim().equals(""))) {
			return 0;
		} else if (s1 == null || s1.trim().equals("")) {
			return -1;
		} else if (s2 == null || s2.trim().equals("")) {
			return 1;
		}
		String[] arr1 = s1.split("[^a-zA-Z0-9]+"), arr2 = s2
				.split("[^a-zA-Z0-9]+");

		int i1, i2, i3;

		for (int ii = 0, max = Math.min(arr1.length, arr2.length); ii <= max; ii++) {
			if (ii == arr1.length)
				return ii == arr2.length ? 0 : -1;
			else if (ii == arr2.length)
				return 1;

			try {
				i1 = Integer.parseInt(arr1[ii]);
			} catch (Exception x) {
				i1 = Integer.MAX_VALUE;
			}

			try {
				i2 = Integer.parseInt(arr2[ii]);
			} catch (Exception x) {
				i2 = Integer.MAX_VALUE;
			}

			if (i1 != i2) {
				return i1 - i2;
			}

			i3 = arr1[ii].compareTo(arr2[ii]);

			if (i3 != 0)
				return i3;
		}
		return 0;
	}
	/**
	 * 判断是否是安卓用户
	 * @param channel
	 * @return
	 */
	public static boolean isAndroidUser(String channel) {
		if ("1".equals(channel) || "1101".equals(channel)
				|| "1201".equals(channel) || "1301".equals(channel)
				|| "1401".equals(channel) || "1501".equals(channel)
				|| "1601".equals(channel) || "1701".equals(channel)
				|| "1801".equals(channel) || "1901".equals(channel)
				|| "2001".equals(channel) || "2101".equals(channel)
				|| "2201".equals(channel)|| "2301".equals(channel)
				|| "2401".equals(channel)|| "2501".equals(channel)
				|| "2601".equals(channel)|| "2701".equals(channel)
				|| "2801".equals(channel)|| "2901".equals(channel)
				|| "3001".equals(channel)|| "3101".equals(channel)
				|| "3201".equals(channel)|| "3301".equals(channel)
				|| "3401".equals(channel)|| "3501".equals(channel)
				|| "3601".equals(channel))  {
			return true;
		}
		return false;
	}

	/**
	 * 文件服务URL地址补全
	 * @param path
	 * @param url
	 * @return
	 */
	public static String normalizeFileUrl(String path, String url) {
		if (url == null || url .equals("") ||url.startsWith("http:") || url.startsWith("https:")){
			return url;
		}	
		StringBuilder rv = new StringBuilder(Config.getStr("app.zjfile"));
		if (!url.startsWith("/")) {
			rv.append(path);
		}
		rv.append(url);
		return rv.toString();
	}

	/**
	 * 版本判断
	 * @param channelId
	 * @param versionId
	 * @param default_androidVersion
	 * @param default_iosVersion
	 * @return
	 */
	public static boolean versionCheck(String channelId, String versionId,
			String default_androidVersion, String default_iosVersion) {
		if (isAndroidUser(channelId)) {
			// 当前版本大于基础版本
			if (compare(versionId, default_androidVersion) >= 0) {
				return true;
			}
		} else if ("2".equals(channelId) && !"".equals(versionId)) {
			if (compare(versionId, default_iosVersion) >= 0) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 判断是否是新用户
	 * @param acc
	 * @param ms2
	 * @return 新用户返回true
	 */
	public static boolean ifNewUser(Account acc, InviteInfo info,final long ms2){
		//1)首登时间=当天 && 2）绑定时间=当天或者未绑定 或者3）从未登录过手厅
		if(acc==null){
			return true;
		}else if(isSameDayOfMillis(Long.parseLong(acc.getM_firstlogin().toString()), ms2)
				&&(info.getInvited_code()==null||isSameDayOfMillis(Long.parseLong(info.getInvite_time().toString()),ms2))){
			return true;
		}else{
			return false;
		}
	}

	public static boolean ifNewUserForApp(Account acc, InviteInfo info,final long ms2){
		if(acc==null){
			return false;
		}else if(isSameDayOfMillis(Long.parseLong(acc.getM_firstlogin().toString()),ms2)
				&&(info.getInvited_code()==null||isSameDayOfMillis(Long.parseLong(info.getInvite_time().toString()),ms2))){
			return true;
		}else{
			return false;
		}
	}

	/**
	 * 判断两个时间是否是同一天
	 * @param ms1
	 * @param ms2
	 * @return
	 */
	public static boolean isSameDayOfMillis(final long ms1, final long ms2) {
        final long interval = ms1 - ms2;
        return interval < MILLIS_IN_DAY
                && interval > -1L * MILLIS_IN_DAY
                && toDay(ms1) == toDay(ms2);
    }

	public static long toDay(long millis){
		return (millis + TimeZone.getDefault().getOffset(millis)) / MILLIS_IN_DAY;
	}


	/**
	 * 生成邀请码
	 */
    public static String getInviteCode(int length) {

        StringBuffer val = new StringBuffer();
        Random random = new Random();

		  //参数length，表示生成几位随机数
		for(int i = 0; i < length; i++) {
			String charOrNum = random.nextInt(2) % 2 == 0 ? "char" : "num";
			String a="";
		 //输出字母还是数字
			if( "char".equalsIgnoreCase(charOrNum) ) {
				int temp = 97;
				do{
					a =String.valueOf((char)(random.nextInt(26)+temp));
				}while(StringUtils.equals(a, "o")||StringUtils.equals(a, "l"));
			} else if( "num".equalsIgnoreCase(charOrNum) ) {
				do{
					a = String.valueOf(random.nextInt(10));
				}while(StringUtils.equals(a, "0")||StringUtils.equals(a, "1"));
		    }
			val.append(a);
		}
		return val.toString();
    }

    /**
     * 判断号码是否有效【返回格式数据[0]:是否为浙江号码 [1]:归属地市or错误信息】
     * @param num
     * @param title
     * @param ip
     * @return
     */
    public static String[] checkNum(String num){
    	String[] res=new String[2];
    	Object obj=null;
    	if(CacheUtil.useable()){
    		obj=CacheEnum.USERCITY.getCache(num);
    	}
    	if(obj==null){
    		String cityNo = "";
    		//判断号码是否有效
    		try {
    			Document doc = XMLRequest.ESB_CS_QRY_MULTI_MULTIQRY_012(num).execute3();
    			ZMCCInternalException.checkESB(doc, false);
    			Element info = doc.getRootElement().element("BUSI_INFO");
    			cityNo = info.elementText("REGION_CODE");
    			res[0]="0";
    			res[1]=cityNo;
    			if(CacheUtil.useable()){
        			CacheEnum.USERCITY.setCache(num, res[0]+","+res[1]);
        		}
    		} catch (ZMCCInternalException e) {
    			res[0]="1";
    			res[1]=e.getErrorMsg();
    		}catch(Exception e){
    			res[0]="1";
    			res[1]="服务异常,请稍后再试!";
    		}
    	}else{
    		String result=(String)obj;
    		res=result.split(",");
    	}
		return res;
    }

    /**
     * 获取客户端各渠道、版本对应的RSA公钥
     * @param channelId
     * @param versionId
     * @return
     */
    public static String getClientRsaPublicKey(String channelId, String versionId){
    	if(channelId==null||"".equals(channelId)||versionId==null||"".equals(versionId)) {return "";}
    	boolean flag=isAndroidUser(channelId);
    	String version=versionId.replace(".", "_");
    	StringBuffer key=new StringBuffer("rsaclient.public_key_");
    	if(flag){
    		key.append("1_");
    		key.append(version);
    		return Config.getStr(key.toString());
    	}else if("2".equals(channelId)){
    		key.append("2_");
    		key.append(version);
    		return Config.getStr(key.toString());
    	}
    	return "";
    }

    /**
     * 获取客户端各渠道、版本对应的RSA私钥
     * @param channelId
     * @param versionId
     * @return
     */
    public static String getClientRsaPrivateKey(String channelId, String versionId){
    	if(channelId==null||"".equals(channelId)||versionId==null||"".equals(versionId)) {return "";}
    	boolean flag=isAndroidUser(channelId);
    	String version=versionId.replace(".","_");
    	StringBuffer key=new StringBuffer("rsaclient.private_key_");
    	if(flag){
    		key.append("1_");
    		key.append(version);
    		return Config.getStr(key.toString());
    	}else if("2".equals(channelId)){
    		key.append("2_");
    		key.append(version);
    		return Config.getStr(key.toString());
    	}
    	return "";
    }

    /**
     * 获取服务端各渠道、版本对应的RSA公钥
     * @param channelId
     * @param versionId
     * @return
     */
    public static String getServerRsaPublicKey(String channelId, String versionId){
    	if(channelId==null||"".equals(channelId)||versionId==null||"".equals(versionId)) {return "";}
    	boolean flag=isAndroidUser(channelId);
    	String version=versionId.replace(".", "_");
    	StringBuffer key=new StringBuffer("rsaserver.public_key_");
    	if(flag){
    		key.append("1_");
    		key.append(version);
    		return Config.getStr(key.toString());
    	}else if("2".equals(channelId)){
    		key.append("2_");
    		key.append(version);
    		return Config.getStr(key.toString());
    	}
    	return "";
    }

    /**
     * 获取服务端各客户端渠道、版本对应的RSA私钥
     * @param channelId
     * @param versionId
     * @return
     */
    public static String getServerRsaPrivateKey(String channelId, String versionId){
    	if(channelId==null||"".equals(channelId)||versionId==null||"".equals(versionId)) {return "";}
    	boolean flag=isAndroidUser(channelId);
    	String version=versionId.replace(".", "_");
    	StringBuffer key=new StringBuffer("rsaserver.private_key_");
    	if(flag){
    		key.append("1_");
    		key.append(version);
    		return Config.getStr(key.toString());
    	}else if("2".equals(channelId)){
    		key.append("2_");
    		key.append(version);
    		return Config.getStr(key.toString());
    	}
    	return "";
    }
    /**
     * 请求合法性检查
     * @param vcode 校验码
     * @param rcode 会话密码
     * @param skey  skey值
     * @param strings 各请求参数
     * @return
     */
    public static boolean validCheck(String vcode,LinkedList<String> list){
    	try {
	    	StringBuffer sf=new StringBuffer();
	    	for (int i = 0; i < list.size(); i++){
	    		sf.append(list.get(i));
	    	}
			if(vcode.equals(SHAUtil.shaEncode(sf.toString()))){
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return false;
    }



    public static boolean checkSet(String num) throws ZMCCInternalException{
		Document doc = YHXMLRequest.DOUBLE_SEVENTH(num).execute7();
		Element head = doc.getRootElement().element("HEAD");
		Element body = doc.getRootElement().element("BODY");
		String state = body.elementText("STATE");
		String code = head.elementText("ERROR_CODE");
		if ("1".equals(state)&&"0".equals(code)) {
			return true;
		}else{
			return false;
		}
	}

	public static void webLeve(HttpServletRequest request, Account acc,
			Object rv, Date startTime, String errCode, String errMsg,
			String servlet) {
		String tag;
		try {
			if ("StarLevel".equalsIgnoreCase(servlet)
					|| "OpStarLevel".equalsIgnoreCase(servlet)) {
				Date endTime = new Date();
				JSONObject result = (JSONObject) JSON.toJSON(rv);
				if (!"0".equals(result.get("result").toString())
						|| "".equals(result.get("result").toString())
						|| null == result.get("result").toString()) {
					tag = "1";
				} else {
					tag = "0";
				}
				String state = DictionaryUtil.typeAndDateCodeToName("JY006",
						"STATE");
				TLogBase.getInstance()
						.getLogService()
						.addTlogbaseAll(acc.getId().toString(), errCode,
								errMsg, "", state, "", startTime, endTime, "2",
								tag, ServletUtil.getRealIp(request), "", "", "", "");
			}
		} catch (Exception e) {
			loggin.info("星级查询报错：" + e.getMessage(), e);
		}
	}

	

	/**
	 * @author chenhua
	 * expiry毫秒
	 * 判断当前key是否存在缓存,不存在则保存
	 * */
	public static boolean isExistReq(HttpServletRequest request, int expiry) {
		String key = null;
		StringBuilder sb = new StringBuilder();
		try {
			sb.append(request.getServletPath())
					.append(request.getQueryString() == null ? "" : "?"
							+ request.getQueryString()).append("_")
					.append(ServletUtil.getRealIp(request)).toString();
			key = MD5.getInstance().getMD5ofStr(sb.toString());
			if (key == null){
				return false;
			}
			boolean ifRepeat = CommFunc.checkRepeatRequest(key,
					"",expiry);
			if (ifRepeat) {
				// 不要重复请求
				return ifRepeat;
			}
		} catch (Exception e) {
			return false;
		}
		return false;
	}

	/**限制字符串长度
	 * @param str
	 * @param length
	 * @return  cjs
	 */
	public static String getRestriction(String str, int length) {
		// 只允许字母和数字和汉字
		String regExS = "[^a-zA-Z0-9\u4e00-\u9fa5]";
		Pattern p = Pattern.compile(regExS);
		Matcher m = p.matcher(str);
		String sp = m.replaceAll("").trim();
		return sp.substring(0, (sp.length() > length) ? length : sp.length());
	}

	/**
	 *  多次请求校验
	 * @param num  手机号码
	 * @param servletName  接口名称
	 * @param maxTime  最大调用次数
	 * @return
	 */
	public static boolean valid(long num, String servletName, int maxTime) {

		Object obj = CacheEnum.REPEAT.getCache(num + CacheEnum.KEY_SEPARATOR
				+ servletName);
		if (obj == null) {
			CacheEnum.REPEAT.setCache(num + CacheEnum.KEY_SEPARATOR
					+ servletName, 1);
		} else {
			Integer repeat_num = (Integer) CacheEnum.REPEAT.getCache(num
					+ CacheEnum.KEY_SEPARATOR + servletName);
			repeat_num++;
			CacheEnum.REPEAT.setCache(num + CacheEnum.KEY_SEPARATOR
					+ servletName, repeat_num);
			if (repeat_num > maxTime) {
				return false;
			}
		}
		return true;
	}
	/**
	 *  多次请求校验
	 * @param num  手机号码
	 * @param servletName  接口名称
	 * @param maxTime  最大调用次数
	 * @return
	 */
	public static boolean valid(String ip, String servletName, int maxTime) {

		Object obj = CacheEnum.REPEAT.getCache(ip + CacheEnum.KEY_SEPARATOR
				+ servletName+"1");
		if (obj == null) {
			CacheEnum.REPEAT.setCache(ip + CacheEnum.KEY_SEPARATOR
					+ servletName+"1", "1");
		} else {
			String repeat_str = (String) CacheEnum.REPEAT.getCache(ip
					+ CacheEnum.KEY_SEPARATOR + servletName+"1");
			Integer repeat_num = Integer.parseInt(repeat_str);
			repeat_num++;
			CacheEnum.REPEAT.setCache(ip + CacheEnum.KEY_SEPARATOR
					+ servletName+"1", repeat_num.toString());
			if (repeat_num > maxTime) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 实名制认证
	 * 
	 * @param accountNum
	 *            账户编号
	 * @param type
	 *            账户类型 1 手机号 2 其他
	 * @param cityNo
	 *            地址编号
	 * @param
	 * @return 0：验证通过,1 ：验证不通过，2:接口超时
	 */
	public static String realNameValid(String accountNum, int type,
			String cityNo, HttpServletRequest request) {
		boolean resuliType = false;
		String result = "1";
		String errorCode = "";
		String errorMsg = "";
		String resultValue = "";
		try {
			String into = DictionaryUtil.typeAndDateCodeToName(
					Constant.REAL_NAME_CODE, "STATE");
			if ("FALSE".equalsIgnoreCase(into) || StringUtils.isEmpty(into)) { // 不验证
				resuliType = true;
				result = "0";
				return result;
			} else { // 全部验证||验证地市
				String[] cityNos = into.split(","); // 获得所有需要验证的地市编号
				if (!"TRUE".equalsIgnoreCase(cityNos[0])) {
					if (!Arrays.asList(cityNos).contains(cityNo)) {
						resuliType = true;
						result = "0";
						return result;
					}
				}
				// 调用炎黄的接口开始校验
				ProcessLogUtil.fillPara(accountNum,LogProcessEnum.NATURE_CHECK,"实名制认证");
				Document doc = YHXMLRequest.REAL_NAME_VALID(accountNum,
						String.valueOf(type)).execute7();
				ZMCCInternalException.checkYH(doc, false);
				Element head = doc.getRootElement().element("HEAD");
				errorCode = head.elementText("ERROR_CODE");
				errorMsg = head.elementText("ERROR_MSG");
				if ("0".equals(errorCode)) {
					Element body = doc.getRootElement().element("BODY");
					resultValue = body.elementText("RESULT_VALUE");
					errorMsg += " : " + body.elementText("ERROR_MSG");
				}
				if (!"Y".equalsIgnoreCase(resultValue)) {
					return result;
				}
				resuliType = true;
				result = "0";
				return result;
			}
		} catch (ZMCCInternalException ex) {
			errorCode = ex.getErrorCode();
			errorMsg = ex.getErrorMsg();
			if("9000".equals(errorCode)){
				result = "2";
			}
			return result;
		} catch (Exception e) {
			result = "2";
			errorCode = "2";
			errorMsg = "程序异常...";
			e.printStackTrace();
		} finally {
			// 记日志
			TLogBase.getInstance()
					.getLogService()
					.addTlogbase(accountNum, errorCode, errorMsg, "",
							"充值实名制验证", "", null, null, "2", resuliType ? "0" : "1",
									ServletUtil.getRealIp(request), "");
		}
		return result;
	}

	/**
	 * 随机数生成字符串
	 * 
	 * @param length
	 *            生成字符串的长度
	 * @return
	 */
	public static String randomStr(int length) {
		Random randGen = null;
		char[] numbersAndLetters = null;
		if (length < 1) {
			return null;
		}
		if (randGen == null) {
			randGen = new Random();
			numbersAndLetters = ("0123456789abcdefghijklmnopqrstuvwxyz"
					+ "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ").toCharArray();
			// numbersAndLetters =
			// ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ").toCharArray();
		}
		char[] randBuffer = new char[length];
		for (int i = 0; i < randBuffer.length; i++) {
			randBuffer[i] = numbersAndLetters[randGen.nextInt(71)];
			// randBuffer[i] = numbersAndLetters[randGen.nextInt(35)];
		}
		return new String(randBuffer);
	}

	/**
	 * 隐藏手机号中间四位
	 * 
	 * @param num
	 * @return
	 */
	public static String hidePartNum(String num) {
		if (num == null || "".equals(num) || num.length() != 11) {
			return "";
		} else {
			return num.substring(0, 3) + "****"
					+ num.substring(num.length() - 4, num.length());
		}
	}

	/**
	 * 将新用户开始写入排名表
	 * 
	 * @param acc
	 *            用户信息
	 * @param channel
	 *            渠道
	 */
	public static void saveToUserRank(Account acc, boolean flag) {
		try {
			if (flag) {
				loggin.info("手厅渠道进入，开始入库操作");
				String tableName1 = "user_rank";
				String tableName2 = "user_rank_" + acc.getCityNo();
				UserRankFactory urfc = new UserRankFactory();
				boolean flag1 = urfc.insert(tableName1, acc);
				loggin.info("插入结果" + tableName1 + "：flag：" + flag1);
				boolean flag2 = urfc.insert(tableName2, acc);
				loggin.info("插入结果" + tableName2 + "：flag：" + flag2);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 将新用户写入首登用户群表
	 * @param num 用户号码
	 */
	public static void saveToFirstLogin(long num,String type) {
		try {
			//新用户首登送活动
			loggin.info("进入首登新用户群插入方法！！！！！！！！");
			McUserFirstLoginFactory mcUserFirstLoginFactory = new McUserFirstLoginFactory();
			Calendar c = Calendar.getInstance();
			String date = new SimpleDateFormat("yyyyMM").format(c.getTime());
            String tableName = "USER_FIRSTLOGIN_" + date;

			//查询是否有该表，如果没有则创建该表
			int count = mcUserFirstLoginFactory.selectCount(tableName);
			boolean b;
			if(count == 0){
				b=mcUserFirstLoginFactory.createUsersFirstLogin(tableName);
				if(b){
					loggin.info("创建首登新用户群表"+tableName+"成功！！！");
				}else {
					loggin.info("创建首登新用户群表"+tableName+"失败！！！");
				}
			}else {
				loggin.info(tableName+"已存在！！！");
				b=true;
			}
			//新用户插入用户群表
			if (!"".equals(tableName)&&b) {
				mcUserFirstLoginFactory.insertUser(tableName, String.valueOf(num),type);
				loggin.info("成功插入首登新用户群！！！！！！！！");
			}
		} catch (Exception e) {
			e.printStackTrace();
			loggin.info("插入首登新用户群失败！！！！！！！！");
		}
	}

	/**
	 * 将新增首登用户信息写入kafka
	 * @param num 用户号码
	 */
	public static void saveTokfkFirstLogin(long num) {
		//新增首登用户信息写入kafka
		try{
			SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmssSSS");
			String time =  formatter.format(new Date());
			String uuid = CommFunc.getUUID();
			String data = "{\"failCount\":0,\"fields\":{\"list\":[{\"template\":\"862165307\",\"taskid\":\"987bsds61-61sdsf-skdjksjs83-360a43sds01\",\"sendto\":"+ num + ",\"info\":{}}]},\"operation\":\"MsgPush\",\"system\":\"spark-test\",\"time\":"+ time + ",\"uuid\":\""+uuid+"\"}";
			//调用kafka的sendMessage方法
			SjyytKafkaProducer.sendMessage(KafkaTopicEnum.first_login, String.valueOf(num),data);
		} catch (Exception e) {
			loggin.error("kafka首次登录日志记录错误:" + e.getMessage(), e);
		}
	}

	/**
	 * 判断当前版本是否属于最低版本与最高版区间内
	 * 
	 * @param myVersion
	 * @param minVersion
	 * @param maxVersion
	 * @return(minVersion<=myVersion<=maxVersion return true)
	 */
	public static boolean compareVersion(String myVersion, String minVersion,
			String maxVersion) {
		if (compare(myVersion, minVersion) < 0) {// 当前版本小于最低版本
			return false;
		}
		if (maxVersion != null && !"".equals(maxVersion)
				&& compare(myVersion, maxVersion) > 0) {// 当前版本大于最高版本
			return false;
		}
		return true;
	}

	/**
	 * 限制提交订单的频率
	 * @param map
	 * @param num
	 * @param channel
	 * @param accountId
	 * @param ip
	 * @return map
	 */
		public static Map<String, Object> frequencyLimit(Map<String, Object> map,String num,String channel,String accountId,String ip,HttpServletRequest request) {
			//限制提交订单的频率
			// 申明变量
			Date startTime = null;
			Date endTime = null;
			String resultflag = "0";
			String errorCode = "";
			String errorMsg = "";
			Document doc = null;

			String menuId = "";
			loggin.info("channel ====== " + channel);
			channel = channel == null || channel.isEmpty() ? "0" : channel;
			try {
				//获取menuid
				menuId = CommFunc.getMenuId(channel);
				String[] dates = QueryConOrderInfo.covTime("0").split("-");
				String start_time = dates[0];
				String end_time = dates[1];
				//调宽带查询接口
				YHXMLRequestNew xmlRequest = YHXMLRequestNew.KT_BB_ORDERINFO_QRY_03(num, menuId,start_time,end_time,request);
				doc = xmlRequest.execute7();
//				doc = DocumentHelper.parseText("<ORDER_INFO><ID>kdxbISX7P7QUF4L1E3K19RA4H40M</ID><PRODUCT_ID>8ace47a55707d503015708d4fadc09cf</PRODUCT_ID><OFFER_NAME>20M包2年900元</OFFER_NAME><MARKET_PROG_ID>600000345461</MARKET_PROG_ID><OFFER_ID>600000267464</OFFER_ID><MARKET_KIND_ID>600000345479</MARKET_KIND_ID><PRE_ORDER_ID>76002209430191</PRE_ORDER_ID><TYPE>2</TYPE><ACCOUNT>tzwlc58675665</ACCOUNT><TRANSACT_TIME>2016-09-10 21:12:59</TRANSACT_TIME><BILL_ID>13958675665</BILL_ID><CERTIFICATE_TYPE></CERTIFICATE_TYPE><CERTIFICATE_NO></CERTIFICATE_NO><CITY>576</CITY><COUNTY>5765</COUNTY><INSTALL_ADDRESS></INSTALL_ADDRESS><CONTACT_NAME>网</CONTACT_NAME><CONTACT_PHONE>13958675665</CONTACT_PHONE><PRE_DATE></PRE_DATE><INVOICE_NAME></INVOICE_NAME><PREPAY_BILL_ID></PREPAY_BILL_ID><DISCOUNT_FEE>0</DISCOUNT_FEE><PAY_MENT>900</PAY_MENT><CREATE_TIME>2016-09-10 21:12:57</CREATE_TIME><UPDATE_TIME>2016-09-10 21:12:59</UPDATE_TIME><OPERATOR></OPERATOR><PAY_WAY_STATE>2</PAY_WAY_STATE><STATUS>1</STATUS><WM_ID></WM_ID><XJ_WM_ID></XJ_WM_ID><AD_ID></AD_ID><C_ID></C_ID><SHOP_ID></SHOP_ID><MEMBER_TYPE></MEMBER_TYPE><PAY_CHANNEL>4</PAY_CHANNEL><PAY_WAY></PAY_WAY><PLAN_TYPE>0</PLAN_TYPE><REFERENCE></REFERENCE><BACK_BILL_ID>13958675665</BACK_BILL_ID><DISCOUNT_LIST><DISCOUNT_INFO><DISCOUNT_ID>8ace47a5547cc27701548399a84f4d7c</DISCOUNT_ID><DISCOUNT_NAME>线上专享</DISCOUNT_NAME><DISCOUNT_TEXT>续费送抽奖机会，最高#{#500#}#元话费券。</DISCOUNT_TEXT><DISCOUNT_CITY>0</DISCOUNT_CITY></DISCOUNT_INFO><DISCOUNT_INFO><DISCOUNT_ID>8ace47a555495ada01555311c47b4ed3</DISCOUNT_ID><DISCOUNT_NAME>送300话费</DISCOUNT_NAME></ORDER_INFO>");

				ZMCCInternalException.checkYH(doc, false);
				Element body = doc.getRootElement().element("BODY");
				Element offerList = body.element("ORDER_LIST");

				//遍历宽带订单判断重复提交
				if (offerList.elements("ORDER_INFO").size() != 0) {
					for (Object info : offerList.elements("ORDER_INFO")) {
						Element accountInfo = (Element) info;
						String type = accountInfo.elementText("TYPE");
						String status = accountInfo.elementText("STATUS");
						String accound = accountInfo.elementText("ACCOUNT");
						String transacttime = accountInfo.elementText("TRANSACT_TIME");
						if (("1".equals(type) || "5".equals(type) || "6".equals(type) || "2".equals(type)) && !"6".equals(status)) {
							//如果同一个宽带账号已经在下单成功的记录时间与当前系统时间的间隔在600秒之内（不含600秒）返回map
							SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
							if (accountId.equals(accound) && DateUtil.difTimeForMin(df.parse(transacttime)) < 10) {//小于10分钟，返回订单提交过于频繁
								map.put("result", "1");
								map.put("msg", "您提交订单过于频繁，请稍后再试。");
								return map;
							}
						}
					}
				}

				//调宽带代客查询接口
				YHXMLRequestNew xmlRequest2 = YHXMLRequestNew.KT_BB_ORDERINFO_QRY_04(num, menuId,start_time,end_time,request);
				Document document = xmlRequest2.execute7();
				ZMCCInternalException.checkYH(document, false);
				Element bodys = document.getRootElement().element("BODY");
				Element offerLists = bodys.element("ORDER_LIST");

				//遍历宽带代客查询订单判断重复提交
				if (offerLists.elements("ORDER_INFO").size() != 0) {
					for (Object info : offerLists.elements("ORDER_INFO")) {
						Element accountInfo = (Element) info;
						String type = accountInfo.elementText("TYPE");
						String status = accountInfo.elementText("STATUS");
						String accound = accountInfo.elementText("ACCOUNT");
						String transacttime = accountInfo.elementText("TRANSACT_TIME");
						if (("1".equals(type) || "5".equals(type) || "6".equals(type) || "2".equals(type)) && !"6".equals(status)) {
							SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
							//如果同一个宽带账号已经在下单成功的记录时间与当前系统时间的间隔在600秒之内（不含600秒）返回map
							if (accountId.equals(accound) && DateUtil.difTimeForMin(df.parse(transacttime)) < 10) {//如果小于10，返回重复下单
								map.put("result", "1");
								map.put("msg", "您提交订单过于频繁，请稍后再试。");
								return map;
							}
						}
					}
				}
			} catch (Exception e) {
				loggin.error("宽带新装预约订单！！！" + e);
				e.printStackTrace();
				resultflag = "1";
				ZMCCInternalException ee = null;
				if (e instanceof ZMCCInternalException) {
					ee = (ZMCCInternalException) e;
					errorCode = ee.getErrorCode();
					errorMsg = ee.getErrorMsg();
				}
			}finally {
				// 记日志
				TLogBase.getInstance().getLogService().addTlogbase(num, errorCode, errorMsg, "", "宽带订单", "",
						startTime, endTime, "2", resultflag, ip, "");
			}
			return map;
		}

	/**限制字符串长度
	 * @param str
	 * @param length
	 * @return  true 符合标准
	 */
	public static boolean checkLen(String str, int length) {
		if(str == null || str.length()==length){
			return false;
		}else{
			return true;
		}
	}

	/**
	 * 获取当前字符串的字符集 【不推荐使用】
	 * @return
	 */

	public static String getStrEncoding(String str){
		try {
			for(String encode:encodes){
				if(str.equals(new String(str.getBytes(encode), encode))){
					return encode;
				}
			}
		} catch (UnsupportedEncodingException e) {
		}
		return "UTF-8";
	}


	/**
	 * 根据字符集转化  【不推荐使用】
	 * @param str
	 * @return
	 */
	public static String changeEncoding(String str) {
		try {
			if(str==null){
				return str;
			}
			String encode = getStrEncoding(str);
			if("GB2312".equals(encode)){
				return str;
			}else{
				String newStr=new String(str.getBytes(encode), "UTF-8").trim();
				return newStr;
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return str;
	}


	/**
	 * 前端必须传入 charset=中   参数
	 * @param request
	 * @return
	 */
	public static String getStrEncoding(HttpServletRequest request){
		String charsetExp = ServletUtil.getStrParamter(request, "charset");
		String charset="UTF-8";
		if(charsetExp!=null&&!charsetExp.equals("中")){
			for(String a: encodes){
				String charsetExp2=null;
				try {
					charsetExp2 = new String(charsetExp.getBytes(a), "UTF-8");
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				if("中".equals(charsetExp2)){
					charset=a;
					loggin.error("使用以下编码："+charset);
					break;
				}
			}
		}
		return charset;
	}

	public static String getStrEncodingTest(String charsetExp){
		String charset="UTF-8";
		if(charsetExp!=null&&!charsetExp.equals("中")){
			for(String a: encodes){
				String charsetExp2=null;
				try {
					charsetExp2 = new String(charsetExp.getBytes(a), "UTF-8");
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				if("中".equals(charsetExp2)){
					charset=a;
					break;
				}
			}
		}
		return charset;
	}

	/**
	 * 根据前端传入的中字，获取服务器编码，如果是乱码 则进行编码；
	 * @param request
	 * @param str
	 * @return
	 */
	public static String changeEncoding(HttpServletRequest request, String str){
		String charset = getStrEncoding(request);
		String changeAfterStr = "";
		if(StringUtils.isBlank(str))
			return "";
		try {
			loggin.info("str--before--------"+str);
			changeAfterStr = new String(str.getBytes(charset),"UTF-8");
			loggin.info("str--after--------"+str);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return changeAfterStr;
	}


	
	public static String getMenuId(String ch){
		String menuId = "";
		SysDictionary sd = DictionaryUtil.findDicData(Constant.KD_MENU_ID,ch);
		if(sd!=null&&sd.getDataDesc()!=null&&!"".equals(sd.getDataDesc())){
			menuId = sd.getDataDesc();
		}else{
			menuId = "3";
		}
		return menuId;
	}

	

	/**
	 *活动是否下线判断
	 * @param startTime 开始时间
	 * @param endTime  结束时间  结束时间+1天
	 * @return
	 * @throws ParseException
	 */
	public static Map<String, Object> checkIsEffect(String startTime, String endTime) throws ParseException {
		Map<String, Object> map = new HashMap<String, Object>();
		Long now = System.currentTimeMillis();
		SimpleDateFormat format = new SimpleDateFormat("yyyyMMdd");
		Long start = format.parse(startTime).getTime();
		Long end = format.parse(endTime).getTime();
		if (start <= now && end >= now) {
			map.put("result", ResultEnum.SUCCESS.getResult());
		} else {
			map.put("result", ResultEnum.ACTOFFLINE.getResult());
			map.put("msg", ResultEnum.ACTOFFLINE.getMsg());
		}
		return map;
	}


	public static AppActivityInfo getActivityInfoByCache(String id) throws ParseException,SQLException {
		if(id==null||id.equals("")){
			return null;
		}
		AppActivityInfoFactory fact = new AppActivityInfoFactory();
		AppActivityInfo info = null;
		Object obj = CacheEnum.ACTIVITY.getCache(id);
		if (null != obj) {
			info = (AppActivityInfo) obj;
		}
		if (null == info) {
			info = fact.find(Integer.valueOf(id));
			if (null != info) {
				CacheEnum.ACTIVITY.setCache(id, info);
			}
		}
		return info;
	}



	/**
	 * 活动是否下线判断
	 * 活动配置在表中，读缓存
	 *
	 * @param id 活动id
	 * @return
	 * @throws ParseException
	 */
	public static Map<String, Object> checkIsEffect(String id) throws ParseException, SQLException {
		Map<String, Object> map = new HashMap<String, Object>();
		Long now = System.currentTimeMillis();
		AppActivityInfo info=getActivityInfoByCache(id);
		if(null == info) {
			//提示活动下线
			map.put("result", ResultEnum.ACTOFFLINE.getResult());
			map.put("msg", ResultEnum.ACTOFFLINE.getMsg());
		}else{
			Long start = info.getStartTime().getTime();
			Long end = info.getEndTime().getTime();
			if (start <= now && end >= now) {
				map.put("result", ResultEnum.SUCCESS.getResult());
			} else {
				//提示活动下线
				map.put("result", ResultEnum.ACTOFFLINE.getResult());
				map.put("msg", ResultEnum.ACTOFFLINE.getMsg());
			}
		}
		return map;
	}
	/**
	 * 比上一个接口信息更全一点
	 * @param id
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> checkIsEffect2(String id)
			throws Exception {
		Map<String, Object> map = new HashMap<String, Object>();
		Long now = System.currentTimeMillis();
		AppActivityInfo info = getActivityInfoByCache(id);
		
		if (null == info) {
			// 提示活动下线
			map.put("result", ResultEnum.ACTOFFLINE.getResult());
			map.put("msg", ResultEnum.ACTOFFLINE.getMsg());
			
		} else {
			SimpleDateFormat sdf=new SimpleDateFormat("yyyy年MM月dd日");
			SimpleDateFormat sdf2=new SimpleDateFormat("yyyy年MM月dd日 HH:mm:ss");
			Long start = info.getStartTime().getTime();
			Long end = info.getEndTime().getTime();
			if (start <= now && end >= now) {
				map.put("result", ResultEnum.SUCCESS.getResult());
			} else if(start > now){
				// 提示活动下线
				map.put("result", ResultEnum.UnEffect.getResult());
				map.put("msg", ResultEnum.UnEffect.getMsg());
			}else{
				map.put("result", ResultEnum.ACTOFFLINE.getResult());
				map.put("msg", ResultEnum.ACTOFFLINE.getMsg());
			}
			map.put("activeName", info.getActivityName());
			map.put("startDate", sdf.format(info.getStartTime()));
			map.put("startTime", sdf2.format(info.getStartTime()));
			map.put("endTime", sdf2.format(info.getEndTime()));
			map.put("endTime", sdf2.format(info.getEndTime()));
			map.put("city", info.getCity());
			if(info.getEndTime().getHours()==0&&info.getEndTime().getHours()<=15){//如果在当天凌晨10分之前结束，就算前一天
				info.getEndTime().setDate(info.getEndTime().getDate()-1);
				map.put("endDate", sdf.format(info.getEndTime()));
			}else{
				map.put("endDate", sdf.format(info.getEndTime()));
			}
		}
		return map;
	}


	/**
	 * ip请求次数是否超过限制判断
	 * 活动配置在表中，读缓存
	 * @param id 活动id
	 * @param ip 请求ip
	 * @return
	 * @throws ParseException
	 */
	public static Map<String, Object> checkIPLimit(String id,String ip,String num) throws SQLException {
		Map<String, Object> map = new HashMap<String, Object>();
		Date startTime = new Date();
        String objectKey = ip+"+"+id;//请求次数信息缓存的key,按活动区分
		AppActivityIPInfoFactory fact = new AppActivityIPInfoFactory();
		AppActivityIPInfo info = null;//ip请求限制数信息
        AppActivityIPReq reqInfo = null;//ip请求次数信息
		Object obj = CacheEnum.IPLIMIT.getCache(id);//ip请求限制数信息缓存
        Object object = CacheEnum.IPTIMES.getCache(objectKey);//ip请求次数信息缓存,按活动区分
		if (null != obj) {
			info = (AppActivityIPInfo) obj;//获取ip请求限制数信息缓存
		}

		if (null == info) {
			info = fact.find(id);
			if (null != info) {
				CacheEnum.IPLIMIT.setCache(id, info);//设置ip请求限制数信息缓存
			}else {
				//活动未配表示不限制
				map.put("result", ResultEnum.SUCCESS.getResult());
				map.put("msg", ResultEnum.SUCCESS.getMsg());
				return map;
			}
		}

		if (null != object) {
			reqInfo = (AppActivityIPReq) object;//获取ip请求次数信息缓存
		}

		//设置ip请求次数信息缓存

		if (null == reqInfo) {
			reqInfo = new AppActivityIPReq();
			reqInfo.setIp(ip);
			reqInfo.setTimes(1);
		}else {
			int ipTimes = reqInfo.getTimes()+1;
			reqInfo.setTimes(ipTimes);
		}

		int limit = Integer.parseInt(info.limit);//限制请求的次数
		int times = reqInfo.getTimes();//该用户ip请求的次数
		if (times < limit ) {
			int expired = info.getVid();//获取有效期
			CacheEnum.IPTIMES.setExpired(expired);
			CacheEnum.IPTIMES.setCache(objectKey, reqInfo);//设置ip请求次数信息缓存
			map.put("result", ResultEnum.SUCCESS.getResult());
		} else {
			//提示用户请求频繁
			map.put("result", ResultEnum.ACTIPLIMIT.getResult());
			map.put("msg", ResultEnum.ACTIPLIMIT.getMsg());
			// 记日志
			Date endTime = new Date();
			TlogbaseService logbase = new TlogbaseService();
			String errorCode = "1";
			String errorMsg = ip+"IP调用次数已超过限制";
			String resultflag = "1";
			logbase.addTlogbase(num, errorCode, errorMsg, "",
					"用户ip请求次数限制", "", startTime, endTime, "2", resultflag, ip, "");
		}
		return map;
	}
	
	/**
	 * 检测用户的宽带账号状态是否是预销户状态
	 * @param acc
	 * @param menuId
	 * @param request
	 * @return false:预销户状态
	 */
	public static boolean AccountIsOk(String accountId, String menuId, HttpServletRequest request){
		loggin.info("accountId:"+accountId);
		Map<String, Object> map = new HashMap<String, Object>();
		YHXMLRequestNew xmlRequest = null;
		String num = ServletUtil.getStrParamter(request,"num");
		Document doc = null;
		try {
			xmlRequest = YHXMLRequestNew.KT_BB_INFO_QRY(accountId,menuId,request);
			doc = xmlRequest.execute7();
		}catch (Exception e){
			if (BroadbandComm.logError()){
				loggin.error(num + "======KT_BB_INFO_QRY=======accountId:" +accountId +";menuId:"+menuId+";=======异常原因：",e );
			}
		}

		Element body = doc.getRootElement().element("BODY");
		Element accountInfo = body.element("ACCOUNT_LIST").element("ACCOUNT_INFO");
		if(accountInfo != null){
			//STATE  1：在用  2：帐务预销  3：营业预销  4：预开户  5：营业销户  6：帐务销户  7：套卡销户
			//STATE=3的时候为预销户状态
			String accountStatus = accountInfo.elementText("STATE");
			loggin.info("accountStatus:" + accountStatus);
			return !StringUtils.equals("3", accountStatus);
		}
		return true;
	}


	/**
	 * 获取用户地址
	 * @param acc
	 * @param menuId
	 * @param request
	 * @return 用户地址
	 */
	public static String getAddress(String num, String menuId, HttpServletRequest request) throws ZMCCInternalException {

			Document doc = null;
			YHXMLRequestNew xmlRequest = null;
			try {
				xmlRequest = YHXMLRequestNew.KT_BB_INFO_QRY(num, menuId, request);
				doc = xmlRequest.execute7();
			}catch (Exception e){
				if (BroadbandComm.logError()){
					loggin.error(num+"=====KT_BB_INFO_QRY=====num:"+num+";menuId:"+menuId+";异常原因：",e);
				}
			}

			ZMCCInternalException.checkYH(doc, false);
			String citys = DictionaryUtil.typeAndDateCodeToName(Constant.FARE_PAY_CITY_INFO, "STATE");
			Element body = doc.getRootElement().element("BODY");
			String cont_bill_id = body.elementText("CONT_BILL_ID");
			String accounts = "", city = "";
			if (body.element("ACCOUNT_LIST").element("ACCOUNT_INFO") != null) {
				accounts = body.element("ACCOUNT_LIST").element("ACCOUNT_INFO").elementText("ACCOUNT_ID");
			}
			List<Map<String, Object>> infoList = new ArrayList<Map<String, Object>>();
			if (accounts == null || accounts.isEmpty()) {
				return "";
			} else {
				Element accountList = body.element("ACCOUNT_LIST");
				if (accountList != null) {
					for (Object info : accountList.elements("ACCOUNT_INFO")) {
						Map<String, Object> infoMap = new HashMap<String, Object>();
						Element accountInfo = (Element) info;
						String address = accountInfo.elementText("ADDRESS");
						return address;
					}
				}
			}

		return "";
	}


	/**
	 * 获取联系人号码
	 * @param acc
	 * @param menuId
	 * @param request
	 * @return 用户地址
	 */
	public static String getContBillId(String acc, String menuId, HttpServletRequest request) throws ZMCCInternalException {

		Document doc = null;
		YHXMLRequestNew xmlRequest = null;
		try {
			xmlRequest = YHXMLRequestNew.KT_BB_INFO_QRY(acc, menuId, request);
			doc = xmlRequest.execute7();
		}catch (Exception e){
			if (BroadbandComm.logError()){
				loggin.error(acc+"=====KT_BB_INFO_QRY=====num:"+acc+";menuId:"+menuId+";异常原因：",e);
			}
		}

		ZMCCInternalException.checkYH(doc, false);
		Element body = doc.getRootElement().element("BODY");
		String cont_bill_id = body.elementText("CONT_BILL_ID");
		return cont_bill_id;
	}

	/**
	 * 获取用户身份证号
	 * @param acc
	 * @param menuId
	 * @param request
	 * @return 用户地址
	 */
	public static String getCustCertCode(String num, String menuId, HttpServletRequest request) throws ZMCCInternalException {

		Document doc = null;
		YHXMLRequestNew xmlRequest = YHXMLRequestNew.KT_BB_INFO_QRY(num, menuId, request);
		doc = xmlRequest.execute7();
		ZMCCInternalException.checkYH(doc, false);
		Element body = doc.getRootElement().element("BODY");
		String accounts = "";
		if (body.element("ACCOUNT_LIST").element("ACCOUNT_INFO") != null) {
			accounts = body.element("ACCOUNT_LIST").element("ACCOUNT_INFO").elementText("ACCOUNT_ID");
		}
		if (accounts == null || accounts.isEmpty()) {
			return "";
		} else {
			Element accountList = body.element("ACCOUNT_LIST");
			if (accountList != null) {
				for (Object info : accountList.elements("ACCOUNT_INFO")) {
					Map<String, Object> infoMap = new HashMap<String, Object>();
					Element accountInfo = (Element) info;
					String cust_cert_code = accountInfo.elementText("CUST_CERT_CODE");
					return cust_cert_code;
				}
			}
		}

		return "";
	}
	/**
	 * 获取用户姓名
	 * @param acc
	 * @param menuId
	 * @param request
	 * @return 用户地址
	 */
	public static String getContName(String num, String menuId, HttpServletRequest request) throws ZMCCInternalException {

		Document doc = null;
		try {
			YHXMLRequestNew xmlRequest = YHXMLRequestNew.KT_BB_INFO_QRY(num, menuId, request);
			doc = xmlRequest.execute7();
		}catch (Exception e){
			if (BroadbandComm.logError()){
				loggin.error(num+"======KT_BB_INFO_QRY======num:"+num+";menuId:"+menuId+"========异常原因：",e);
			}else {
				throw e;
			}
		}

		ZMCCInternalException.checkYH(doc, false);
		Element body = doc.getRootElement().element("BODY");
		String accounts = "";
		if (body.element("ACCOUNT_LIST").element("ACCOUNT_INFO") != null) {
			accounts = body.element("ACCOUNT_LIST").element("ACCOUNT_INFO").elementText("ACCOUNT_ID");
		}
		if (accounts == null || accounts.isEmpty()) {
			return "";
		} else {
			Element accountList = body.element("ACCOUNT_LIST");
			if (accountList != null) {
				for (Object info : accountList.elements("ACCOUNT_INFO")) {
					Map<String, Object> infoMap = new HashMap<String, Object>();
					Element accountInfo = (Element) info;
					String name = accountInfo.elementText("FIRST_NAME");
					return name;
				}
			}
		}

		return "";
	}
	/**
	 * 是否是外部渠道
	 * @param channel
	 * @return  true  是外部渠道，  false 不是外部渠道
	 */
	public static boolean isOuter(String typecode, String channel){
		if(null==channel){
			return false;
		}
		return StringUtils.isBlank(DictionaryUtil.typeAndDateCodeToName(typecode, channel))?false:true;
	}

    /**
     * 参数非空校验
     *
     * @param map
     * @param args
     * @return
     */
    public static boolean checkParam(Map<String, Object> map, Object... args) {
        boolean flag = false;
        for (int i = 0; i < args.length; i++) {
            if (StringUtils.isBlank((String) args[i])||StringUtils.equals((String) args[i],"undefined")) {
                flag = true;
                map.put("result", ResultEnum.PARAMERR.getResult());
                map.put("msg", ResultEnum.PARAMERR.getMsg());
                break;
            }
        }
        return flag;
    }


	/**
	 * 判断号码是否浙江移动
	 * @param num
	 * @param map
	 * @return true 是
	 */
	public static boolean checkNum(String num, Map<String,Object> map){
		boolean flag = false;
		Object obj=null;
		if(CacheUtil.useable()){
			obj=RedisHome.getObject(RedisCacheEnum.USERLOGIN, num);
		}
		//如果无用户信息，则直接查询用户信息接口
		if(obj==null){
			try {
				ProcessLogUtil.fillPara(num,LogProcessEnum.NATURE_QUERY,"判断号码是否浙江移动-用户信息查询");
				Document doc = XMLRequest.ESB_CS_QRY_MULTI_MULTIQRY_012(num).execute3();
				ZMCCInternalException.checkESB(doc, false);
				flag = true;
			} catch (ZMCCInternalException e) {
				String errorCode = e.getErrorCode();
				if(StringUtils.equals(errorCode,"11100015")){
					map.put("result", "9979");
					map.put("msg","输入号码不是浙江移动的用户号码！");
				}else{
					map.put("result", ResultEnum.OUTSYSTEMERR.getResult());
					map.put("msg",ResultEnum.OUTSYSTEMERR.getMsg());
				}
			}
		}else{
			//如果有用户信息，则取号码类别字段进行判断 号码类别 0：浙江移动号码 1：移动（非浙江） 2：联通号码 3：电信号码
			try {
				Account account = JSON.parseObject(obj.toString(), Account.class);
				String category = account.getCategory();
				//兼容类别为空的情况
				if ("0".equals(category) || category == null) {
					flag = true;
				} else {
					map.put("result", "9979");
					map.put("msg", "输入号码不是浙江移动的用户号码！");
				}
			} catch (Exception e) {
				map.put("result", ResultEnum.OUTSYSTEMERR.getResult());
				map.put("msg", ResultEnum.OUTSYSTEMERR.getMsg());
			}
		}
		return flag;
	}

	public static String getCurrWeekTableName(String tableName){
		Calendar c = Calendar.getInstance();
		int year =  c.get(Calendar.YEAR);
		int week = c.get(Calendar.WEEK_OF_YEAR);
		int day = c.get(Calendar.DAY_OF_WEEK);
		//如果是星期日，则周数减1
		if(day==1){
			week -= 1;
		}
		String result = tableName+"_"+year+week;
		return result;
	}
	
	/**
	 * 根据渠道编号，获取渠道名称
	 * @param ch
	 * @return
	 */
	public static String getChannelName(String ch){
		if(StringUtils.isBlank(ch)){
			ch = "3";
		}
		String name = DictionaryUtil.typeAndDateCodeToName(Constant.KD004,ch);
		if(StringUtils.isBlank(name)){
			name = getChannelName("");
		}
		return name;
	}
	
	
	/**
	 * 判断是否灰度环境
	 * 0 :true 为灰度环境,1 false 为生产环境
	 * @return
	 */
	public static boolean isEnv(){
		int env = 1; // 默认生产环境
		if(Config.getStr("zjenv.env")!=null && !Config.getStr("zjenv.env").equals("")) {
			env = Config.getInt("zjenv.env");
		}
		if(0==env){ //灰度环境
			return true;
		}
		return false;
	}
	/**
	 * 判断是否生产环境
	 * @return
	 */
	public static boolean isPub(){
		int ifPub = 0; // 默认非生产
		try{
			ifPub = Config.getInt("zjenv.ifPub");
		}catch(Exception e){
			
		}
		if(1==ifPub){ //生产环境
			return true;
		}
		return false;
	}
	
	
	/**
	 * 非生产环境下
	 * 将炎黄 报文 转化为String返回给前端
	 * @param map
	 * @param doc
	 */
	public static void putDoc(Map<String, Object> res_map,Document doc,String interno){
		if(isEnv()){
			try {
				Map<String, Object> map = new HashMap<String, Object>();
				if(StringUtils.isBlank(interno)){
					interno = "UNKNOWN";
				}
				String value =  XmlUtil.doc2String(doc);
				map.put("RESP_CONTENT_"+interno,value);
				if(value.contains("<RESP_PARAM>")){
					map.put("REQ_ESB_URL", Config.getStr("esb.url"));
				}else if(value.contains("<RESPONSE>")){
					map.put("REQ_YH_URL", Config.getStr("yh.url"));
				}else if (value.contains("<opr_out>")){
					map.put("REQ_TIC_URL", Config.getStr("tic.url"));
				}
				res_map.put("env."+interno, map);
			} catch (DocumentException e) {
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * 校验和微店参数是否齐全
	 * @param ch
	 * @return
	 */
	public static boolean isWmInfo(String ch, String wm_info){
		loggin.info("ch:"+ch);
		loggin.info("wm_info:"+wm_info);
		if(StringUtils.equals(Constant.HLM_CH, ch)){
			if(StringUtils.isNotBlank(wm_info)){
				String[] wms = wm_info.split("\\|");
				String adid = wms[2];
				String cid = wms[3];
				if(StringUtils.isBlank(adid) || StringUtils.equals(Constant.HLM_DEFAULT_VALUE, adid)
						|| StringUtils.isBlank(cid) || StringUtils.equals(Constant.HLM_DEFAULT_VALUE, cid)){
					return false;
				}
			}else{
				return false;
			}
		}
		return true;
	}
	
	/**
	 * 校验和微店参数是否齐全
	 * @param ch
	 * @param cid
	 * @param adid
	 * @return
	 */
	public static boolean isWmInfo(String ch, String cid, String adid){
		if(StringUtils.equals(Constant.HLM_CH, ch)){
			return StringUtils.isNotBlank(cid) && StringUtils.isNotBlank(adid);
		}
		return true;
	}

	public static String getCertCode(String num,String certType, HttpServletRequest request){
		Date startTime = null;
		Date endTime = null;
		String errorCode = "";
		String errorMsg = "";
		String resultflag = "0";
		try {
			startTime = new Date();
			Document doc = XMLRequestNew.ESB_CS_QRY_MULTI_MULTIQRY_001(num, request).execute3();
			ZMCCInternalException.checkESB(doc, false);
			String cardType = doc.getRootElement().element("BUSI_INFO").element("CUST_INFO").elementText("CARD_TYPE");
			String cardCode = doc.getRootElement().element("BUSI_INFO").element("CUST_INFO").elementText("CARD_CODE");
			String realNameFlag = doc.getRootElement().element("BUSI_INFO").element("CUST_INFO").elementText("REAL_NAME_FLAG");//11：实名制
			if (certType.equals(cardType) && !StringUtils.isBlank(cardCode) && StringUtils.equals("11", realNameFlag)) {
				return cardCode;
			}
			endTime = new Date();
		} catch (ZMCCInternalException e) {
			resultflag = "1";
			errorCode = e.getErrorCode();
			errorMsg = e.getErrorMsg();
		} finally {
			TLogBase.getInstance().getLogService()
					.addTlogbase(num, errorCode, errorMsg,
							"", "密码重置查询三户信息", "", startTime, endTime, "2", resultflag, "", "");
		}
		return "";
	}
	/**
	 * 获取证件号码
	 * @param num      手机号
	 * @param request
	 * @return cardCode 身份证号码
	 */
	public static String getCertCode(String num, HttpServletRequest request) {
		Date startTime = null;
		Date endTime = null;
		String errorCode = "";
		String errorMsg = "";
		String resultflag = "0";
		try {
			startTime = new Date();
			ProcessLogUtil.fillPara(num,LogProcessEnum.NATURE_QUERY,"用户三户信息查询");
			Document doc = XMLRequestNew.ESB_CS_QRY_MULTI_MULTIQRY_001(num, request).execute3();
			ZMCCInternalException.checkESB(doc, false);
			String cardType = doc.getRootElement().element("BUSI_INFO").element("CUST_INFO").elementText("CARD_TYPE");
			String cardCode = doc.getRootElement().element("BUSI_INFO").element("CUST_INFO").elementText("CARD_CODE");
			String realNameFlag = doc.getRootElement().element("BUSI_INFO").element("CUST_INFO").elementText("REAL_NAME_FLAG");//11：实名制
			if ("1".equals(cardType) && !StringUtils.isBlank(cardCode) && StringUtils.equals("11", realNameFlag)) {
				return cardCode;
			}
			endTime = new Date();
		} catch (ZMCCInternalException e) {
			resultflag = "1";
			errorCode = e.getErrorCode();
			errorMsg = e.getErrorMsg();
		} finally {
			TLogBase.getInstance().getLogService()
					.addTlogbase(num, errorCode, errorMsg,
							"", "密码重置查询三户信息", "", startTime, endTime, "2", resultflag, "", "");
		}
		return "";
	}

	/**139 登录直接通过校验
	 * true ： 校验通过
	 * false : 校验失败
	 * @return 
	 */
	public static boolean ifValidNeedLogin(Map<String, Object> map, Account acc, String channel
			, HttpServletRequest request){
		if(StringUtils.equals(Constant.SITE_139_CH, channel)){//不需要登录
			return BroadbandComm.vaildDesAndMd5(map, request) ;
		}else{
			return isLogin(acc);
		}
	}
	
	/**【校验登录请不要使用父类的isLogin变量】 校验登录是否成功
	 * 由于接口需要继承父类OpSpJSONServletBase ,
	 * 大都需要登录的校验都使用父类中的isLogin这个成员变量,
	 * 而isLogin这个变量是静态的,所以在并发的情况下会有问题！
	 * @return  登录 true，  未登录 false  
	 */
	public static boolean isLogin(Account acc){
		if(null==acc){
			return false ;
		}else{
			return true ;
		}
	}
	
	/**
	 * 获取Integer值，null自动转为0
	 * @param str
	 * @return
	 */
	public static Integer getInteger(Object str){
		return str==null?0:Integer.parseInt(str.toString());
	}
	
	/**
	 * 获取String值，null自动转为""
	 * @param str
	 * @return
	 */
	public static String getString(Object str){
		return str==null?"":str.toString();
	}

	/**
	 * 判断的当前时间是否是周日22：00~24：00
	 * @return true 是
	 */
	public static boolean checkTime(){
		boolean flag= false;
		Calendar c = Calendar.getInstance();
		int day = c.get(Calendar.DAY_OF_WEEK);
		if(day == 1){
			int hour = c.get(Calendar.HOUR_OF_DAY);
			if(hour>=22&&hour<=24){
				flag = true;
			}
		}
		return flag;
	}
	/**
	 * 将json串里面的地址都替换成新的地址
	 * @param content
	 * @return
	 */
	public static String replaceUrl(String content,Class cla,HttpServletRequest request){
		boolean ifChange=false;
		boolean ifPub=true;
		try{
			String versionid=request.getParameter("versionid");
			String channel=request.getParameter("channel");
			String channelid=request.getParameter("channelid");
			//可以在这里进行版本，客户端，接口名过滤
			String env=Config.getStr("zjenv.env");
			if(!"1".equals(env)){//准发布
				ifPub=false;
				ifChange=true;
			}else{
				SysDictionary sysDics=DictionaryUtil.findDicData("CF087", "FILE_SWITCH");
				SysDictionary minVersionSd=DictionaryUtil.findDicData("CF087", "MIN_VERSION");
				String minVersion="3.6.2";
				if(minVersionSd!=null&&minVersionSd.getDataDesc()!=null&&!minVersionSd.getDataDesc().equals("")){
					minVersion=minVersionSd.getDataDesc();
				}
				if(sysDics!=null&&"1".equals(sysDics.getDataDesc())){
					int ifVerisonOk=compare(versionid,minVersion);
					if(ifVerisonOk>=0){
						ifChange=true;
					}
				}
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		if(ifChange&&content!=null){
			content=content.replaceAll("app.file.zj.chinamobile.com/file", "app.file.zj.chinamobile.com").replaceAll("app.file.zj.chinamobile.com", "wap.zj.10086.cn/file")
					.replace("app.m.zj.chinamobile.com/zjweb/", "wap.zj.10086.cn/zjweb/");
			//原：http://app.file.zj.chinamobile.com/file/	新：http://wap.zj.10086.cn/file/
			//原：http://app.m.zj.chinamobile.com/zjweb/	       新：http://wap.zj.10086.cn/zjweb/

		}
		
		
		String host=request.getHeader("Host");
		//把非正式环境的域名转换成对应的域名
		if (host != null){
			String dcosGroupId=TlogbaseService.getDcosGroupId();
			String targetHost="";
			boolean ifReplace=false;
			String nginxDcos=DictionaryUtil.typeAndDateCodeToName("CF087", "NGINX_DCOS");
			//虚机是不允许强制切换运营位的，太危险了
			if(dcosGroupId!=null&&!"0".equals(dcosGroupId)&&nginxDcos!=null&&nginxDcos.indexOf(dcosGroupId)>=0){
			//if("1".equals(dcosGroupId)&&"1".equals(nginxDcos)){
				//老的dcos集群,已经作为ng的zjapp了,所以需要转一下运营位域名
				ifReplace=true;
				targetHost="app-web.ng.zj.chinamobile.com";
			}else if(host.startsWith("app-hdapp.yw.zj.chinamobile.com:9000")){
				//这种地址说明是从nginx进来的，因为nginx进来的时候捕获的域名并不是zjweb的
				//但是，也有可能是炎黄或者esb内部接口查询的，所以生产环境不能这样改
				ifReplace=true;
				targetHost="app-hd.zj.chinamobile.com";
			}else if(host.startsWith("10.78.160.81:9000")){
				//这种地址说明是从nginx进来的，因为nginx进来的时候捕获的域名并不是zjweb的
				//但是，也有可能是炎黄或者esb内部接口查询的，所以生产环境不能这样改
				ifReplace=true;
				targetHost="218.205.68.77:8080";
			}else if(host.startsWith("app-hd.zj.chinamobile.com")
					|| host.startsWith("218.205.68.77") || host
					.startsWith("211.140.15.103")){//这种是虚机的
				ifReplace=true;
				targetHost=host;
			}
			//这里配置了需要强转nginx的接口名
			
			//if(isPub()){
			    String positionSwitch=DictionaryUtil.typeAndDateCodeToName("CF087", "POSITION_SWITCH");
				if(positionSwitch!=null){
					String[] positions=positionSwitch.split(",");
					for(String pos:positions){
						if(pos.equals(cla.getSimpleName())){
							ifReplace=true;
							targetHost="app-web.ng.zj.chinamobile.com";
							break;
						}
					}
				}
			//}
			
			if(ifReplace){
				content = content
						.replace("app.m.zj.chinamobile.com/zjweb/",
								"wap.zj.10086.cn/zjweb/")
						.replace("https://wap.zj.10086.cn/zjweb/",
								"http://wap.zj.10086.cn/zjweb/")
						.replace("wap.zj.10086.cn/zjweb/",
								targetHost+"/zjweb/");
			}
			
		}
		
		return content;
	}

	
	/**
	 * 获取券配置信息
	 * @param list
	 * @param tic_type_code
	 * @return
	 */
	public static TicketActivity getTicByCode(List<TicketActivity> list,String tic_type_code){
		TicketActivity tic  = null;
		for(TicketActivity tica: list){
			if(StringUtils.equals(tic_type_code, tica.getCode())){
				tic = tica ;break ;
			}
		}
		return tic;
	}
	
	/**
	 * 如果当前时间不在任何一种类型的券的领取或使用时间内， 则返回false
	 * @param list
	 * @return
	 */
	public static boolean isContain(List<TicketActivity> list){
		Date d = new Date();
		boolean flag = Boolean.FALSE;
		for(TicketActivity tic: list){
			if( (tic.getRecStartTime().before(d) && tic.getRecEndTime().after(d)) 
					|| tic.getUseStartTime().before(d) && tic.getUseEndTime().after(d)){
				flag = Boolean.TRUE;break;
			}
		}
		return flag; 
	}
	
	/**
	 * 当前时间是否在某个时间内
	 * @param ticket
	 * @param f 0 领取时间， 1 使用时间
	 * @return
	 */
	public static boolean ifConAfterTime(TicketActivity tic, int f ){
		boolean flag = Boolean.FALSE;
		Date d = new Date();
		if(tic!=null){
			if(0==f){
				if(tic.getRecStartTime().before(d) && tic.getRecEndTime().after(d)){
					flag = Boolean.TRUE;
				}
			}else if(1==f){
				if(tic.getUseStartTime().before(d) && tic.getUseEndTime().after(d)){
					flag =  Boolean.TRUE;
				}
			}
		}
		return flag;
	}
	
	
	/**
	 * 优惠券是 否在某个时间段内 , 
	 * @param tic 全对象
	 * @param f 0 领取时间， 1 使用时间
	 * @return true 在 ， false 不在
	 */
	public static boolean ifAfterTime(List<TicketActivity> list,String tic_type_code,int f){
		boolean flag = false;
		Date d = new Date();
		TicketActivity tic  = getTicByCode(list, tic_type_code);
		if(tic!=null){
			if(StringUtils.equals(tic_type_code, tic.getCode())){
				if(0==f){
					if(tic.getRecStartTime().before(d) && tic.getRecEndTime().after(d)){
						flag = true;
					}
				}else if(1==f){
					if(tic.getUseStartTime().before(d) && tic.getUseEndTime().after(d)){
						flag = true;
					}
				}
			}
		}
		return flag;
	}

	/**
	 * 是否在使用时间范围内    (提供给  下单之前进行 的一波校验)
	 * 1). 裸宽预受理
	 * 2). 融合预受理
	 * 3). 裸宽融合 意向单受理
	 * @param cou_type_code 优惠券编码
	 * @param cou_code  优惠券消费码
	 * @return  true 在，  false 不在
	 */
	public static boolean ifAfterUserTime(String tic_code,String tic_cou_code){
		boolean ifAfterUserTime = true;
		if(StringUtils.isNotBlank(tic_code) && StringUtils.isNotBlank(tic_cou_code)){
			TicketActivityFactory taf = new TicketActivityFactory();
			List<TicketActivity> ticList = taf.getTicActivityInfo();
			//当前时间是否在领取时间、使用时间内， 如果不在 ，则不能领取
			ifAfterUserTime = CommFunc.ifAfterTime(ticList, tic_code, 1);
		}
		return ifAfterUserTime ;
	}

	/**
	 * 获取白名单信息
	 * @param id  WhiteListEnum 中白名单对应的id,建议直接用下面那个boolean返回的，更方便
	 * @return
	 * @throws SQLException
	 */
	@Deprecated 
	public static Map<String,String> getWhiteListConfig(String id) throws SQLException{
		Map<String,String> map=new HashMap<String,String>();
		String config=RedisHome.getString(RedisCacheEnum.whiteList, id);
		String white_switch="0";
		String mobile_list="";
		if(config==null){
			WhiteListFactory fct = new WhiteListFactory();
			List<WhiteList> list=fct.getWhiteListsById(Integer.parseInt(id));
			//WhiteList record=fct.find(id);
			if(list==null||list.size()==0){
				RedisHome.setString(RedisCacheEnum.whiteList, id, "0|123");//123没有意义的
			}else{
				String billIds="";
				for(WhiteList wl:list){
					billIds+=wl.getMobile_list()+",";
				}
				white_switch="1";
				mobile_list=billIds;
				RedisHome.setString(RedisCacheEnum.whiteList, id, white_switch+"|"+mobile_list);
			}
		}else{
			//白名单缓存内容不规范，则重新获取数据库配置信息，重置缓存
			if(config.indexOf("|")==-1){
				WhiteListFactory fct = new WhiteListFactory();
				List<WhiteList> list=fct.getWhiteListsById(Integer.parseInt(id));
				if(list==null||list.size()==0){
					RedisHome.setString(RedisCacheEnum.whiteList, id, "0|123");//123没有意义的
				}else{
					String billIds="";
					for(WhiteList wl:list){
						billIds+=wl.getMobile_list()+",";
					}
					white_switch="1";
					mobile_list=billIds;
					RedisHome.setString(RedisCacheEnum.whiteList, id, white_switch+"|"+mobile_list);
				}
			}else{
				String[] strs=config.split("\\|");
				white_switch=strs[0];
				mobile_list=strs[1];
			}
		}
		map.put("switch", white_switch);//在缓存和数据库信息都没有的情况，白名单开关为关     0：关闭   1：开启
		map.put("mobile_list", mobile_list);
		return map;
	}
	
	public static boolean ifInWhiteList(String id,String num) throws SQLException{
		if("5".equals(id)&&isPub()){//sso认证测试白名单 & 生产环境，就不查redis了，因为这个开销实在太大了。。。
			return false;
		}
		Map<String,String> map=getWhiteListConfig(id);
		if(map!=null&&"1".equals(map.get("switch"))){
			String mobile_list=map.get("mobile_list");
			if(mobile_list!=null&&mobile_list.indexOf(num)>=0){
				return true;
			}
		}
		return false;
	}
	
	
	/**
	 * 获取EBin平台请求流水号
	 * @return
	 */
	public static String getEBinReqTransNo(){
		String req_trans_no = CommFunc.randomStr(32);
        String req_time = String.valueOf(System.currentTimeMillis());
        String signStr = "REQ_TRANS_NO" + req_trans_no + "REQ_TIME" + req_time;
        req_trans_no = MD5Util.MD5(signStr);
        return req_trans_no;
	}
	
	/**
	 * 
	 * @param numKey
	 * @return true表示是重复请求，false表示不是
	 */
    public static boolean checkRepeatRequest(String num,String activeCode) {
        long result=RedisHome.addString(RedisCacheEnum.RepeatRequest, num + "_" + activeCode, num + "_" + activeCode, 25);
        if(result==1){//添加成功,所以不是重复请求
        	return false;
        }
        return true;
    }
    /**
     * 
     * @param numKey
     * @param expirTime 有效时间
     * @return true表示是重复请求，false表示不是
     */
    public static boolean checkRepeatRequest(String num,String activeCode, int expirTime) {
    	long result=RedisHome.addString(RedisCacheEnum.RepeatRequest, num+"_"+activeCode, num+"_"+activeCode,expirTime);
    	if(result==1){//添加成功,所以不是重复请求
    		return false;
    	}
    	return true;
    }
    
    public static boolean delRepeatRequest(String num,String activeCode) {
        long result=RedisHome.delString(RedisCacheEnum.RepeatRequest, num + "_" + activeCode);
        if(result==1){//删除成功
        	return true;
        }else{//删除失败，key不存在
        	return false;
        }
    }
	public static Map<String, Object> queryAllCity(){
  	 Map<String,Object> map=new HashMap<String,Object>();
		map.put("570", "衢州");//570衢州
		map.put("571", "杭州");//571杭州
		map.put("572", "湖州");//572湖州
		map.put("573", "嘉兴");//573嘉兴
		map.put("574", "宁波");//574宁波
		map.put("575", "绍兴");//575绍兴
		map.put("576", "台州");//576台州
		map.put("577", "温州");//577温州
		map.put("578", "丽水");//578丽水
		map.put("579", "金华");//579金华
		map.put("580", "舟山");//580舟山
		return map;
	}

	/**
	 * 将用户归属地编号转换为抽奖入参中的地区编码
	 * @return
	 */
	public static Map<String,String> changeCityNo(){
		Map<String,String> map=new HashMap<String,String>();
		map.put("570", "098_036_468");//570衢州
		map.put("571", "098_036_360");//571杭州
		map.put("572", "098_036_362");//572湖州
		map.put("573", "098_036_363");//573嘉兴
		map.put("574", "098_036_370");//574宁波
		map.put("575", "098_036_365");//575绍兴
		map.put("576", "098_036_476");//576台州
		map.put("577", "098_036_470");//577温州
		map.put("578", "098_036_469");//578丽水
		map.put("579", "098_036_367");//579金华
		map.put("580", "098_036_364");//580舟山
		return map;
	}
	
	 /***
     *  利用Apache的工具类实现SHA-256加密
     * @param str 加密前字符串
     * @return  加密后的字符串
     */
	public static String getSHA256Str(String str) {
		MessageDigest messageDigest;
		String encdeStr = "";
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
			byte[] hash = messageDigest.digest(str.getBytes("UTF-8"));
			encdeStr = Hex.encodeHexString(hash);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return encdeStr;
	}

	/***
	 *  调用炎黄能力开放平台接口
	 * @param body body
	 * @param interfaceName interfaceName
	 * @return  加密后的字符串
	 */
	public static Document getAbilityOpenDoc(String body , String interfaceName) throws ZMCCInternalException {
		String agent_no = "cson";
		String agent_dep_no = "cson";
		String username = "cson";
		String userpass = "cson";
		String key = "dycdcx#caixunlopiuyhbngfrdeswazx";
		long req_time = System.currentTimeMillis();
		long req_time_limit = req_time + 3*60*1000;
		String req_trans_no = getUUID();
		StringBuffer str = new StringBuffer();
		str.append("agent_no").append(agent_no).append("agent_dep_no").append(agent_dep_no).append("username").append(username)
				.append("userpass").append(userpass).append("req_time").append(req_time).append("req_trans_no")
				.append(req_trans_no).append("body").append(body).append(key);//拼签名参数
		String signature = MD5Util.MD5(str.toString());//签名加密

		StringBuffer content = new StringBuffer();
		//拼接请求参数
		content.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><head><agent_no>cson</agent_no>" +
				"<agent_dep_no>cson</agent_dep_no><username>cson</username><req_time>")
				.append(req_time).append("</req_time><req_trans_no>").append(req_trans_no)
				.append("</req_trans_no><intf_no>").append(interfaceName).append("</intf_no><signature>")
				.append(signature).append("</signature><req_time_limit>").append(req_time_limit)
				.append("</req_time_limit></head><body>"+body+"</body></request>");
		loggin.info("requeststr:"+content);

		Document doc = null;
		try {
			Date start = new Date();
			String url = Config.getStr("yhPlat.url");
			String resultStr = HttpUtil.doHttpPost(url, content.toString(), "utf-8");
			loggin.info(resultStr);
			Date end = new Date();
			loggin.info("耗时：" + (end.getTime() - start.getTime()) / 1000);
			doc = DocumentHelper.parseText(resultStr);
		} catch (DocumentException ex) {
			throw new ZMCCInternalException(9000, "接口服务器繁忙，无法解释的协议");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return doc;
	}
	
	/**
	 * 校验验证码
	 * @param num  手机号
	 * @param code  验证码
	 * @param type  类型
	 * @return
	 */
	public static boolean VaildVerCode(String num,String code,String type){
		SmsVerCodeFactory af = new SmsVerCodeFactory();
		String[] key = { "type="+type+" and MOBILE_PHONE", "CODE" };
		String[] args = { num.trim(), code.trim().toUpperCase()};
		SmsVerCode vc = null;
		try {
			vc = af.find(key, args);
		} catch (SQLException e) {
			loggin.info(String.format("获取数据库验证码失败：%s, %s ,  %s" ,num,code,e));
			return false;
		}
		if (null == vc) {// 图片验证码, 
			af.deteleVerCodeNew(num,type);
			return false;
		}else{
			af.deteleVerCodeNew(num,type);
			return true ;
		}
	}
	
	
	/**
	 * 获取uuid值
	 * @return
	 */
	public static String getUUID() {
		return randomUUID().toString().replaceAll("-", "");
	}
	
	/**
	 * 获取日志打印所需的字符串
	 * @param t
	 * @return
	 */
	public static String getTrace(Throwable t) {   
		StringWriter stringWriter= new StringWriter();   
		PrintWriter writer= new PrintWriter(stringWriter);   
		t.printStackTrace(writer);   
		StringBuffer buffer= stringWriter.getBuffer();   
		return buffer.toString();   
	}
	
	/**
	 * 将单位 为元的金额，转化为 BigDecimal 的分
	 * @param amount
	 * @return
	 */
	public static BigDecimal getAmount(String amount){
		MathContext mc = new MathContext(amount.length(),RoundingMode.HALF_UP);
		BigDecimal orderTotal = new BigDecimal(Double.valueOf(amount)).multiply(new BigDecimal(100),mc);// 支付金额
		return new BigDecimal(String.valueOf((int) Double.valueOf(orderTotal.toString()).doubleValue())) ;
	}

	/**
	 * 限制提交订单的频率
	 * 
	 * @param map
	 * @param num
	 * @param channel
	 * @param accountId
	 * @param ip
	 * @return map
	 */
	public static Map<String, Object> frequencyLimitByOE(Map<String, Object> map, String num, String accountId) {
		String[] dates = QueryConOrderInfo.covTime("0").split("-");
		String start_time = dates[0];
		String end_time = dates[1];
		// 1.2 查询我的订单（订单中心）
		try {
			List<OsOrderVo> oeList = OrderCenterUtil.getBroList("1", num, "", start_time, end_time);
			List<OsOrderVo> oeList_shop = OrderCenterUtil.getBroList("2", num, "", start_time, end_time);
			if (oeList != null) {
				if (oeList_shop != null) {
					oeList.addAll(oeList_shop);
				}
				for (OsOrderVo vo : oeList) {
					if (vo != null) {
						List itemList = vo.getOrderItem();// 获取一级明细 列表
						String crmState = vo.getCrmStatus(); // crm状态
						if (itemList != null && !itemList.isEmpty()) {
							OsOrderItemVo orderItemVo = (OsOrderItemVo) itemList.get(0); // 获取一级明细对象
							String account = orderItemVo.getAccount();
							if (orderItemVo != null) {
								List<OsOrderItemValueVo> orderItemValueList = orderItemVo.getOrderItemValue(); // 获取二级明细列表
								if (orderItemValueList != null && !orderItemValueList.isEmpty()) {
									OsOrderItemValueVo orderItemValue = orderItemValueList.get(0); // 获取二级明细对象
									if (orderItemValue != null) {
										String oe_type = orderItemValue.getBusiType();
										// 如果订单类型还是续包， 且crm 状态 不为空，且同一个宽带账号，
										// 且存在下单时间在10分钟内的
										if (("1".equals(oe_type) || "2".equals(oe_type) || "5".equals(oe_type)
												|| "6".equals(oe_type)||"16".equals(oe_type)||"17".equals(oe_type)) && StringUtils.isNotBlank(crmState)) {// 小于10分钟，返回订单提交过于频繁
											if (accountId.equals(account)
													&& DateUtil.difTimeForMin(vo.getCreateTime()) < 10) {
												map.put("result", "1");
												map.put("msg", "您提交订单过于频繁，请稍后再试。");
												return map;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			map.put("result", "0");
			map.put("vail_msgd", e);
			e.printStackTrace();
		}
		return map;
	}
	/**
	 * 限制提交订单的频率
	 * 
	 * @param map
	 * @param num
	 * @param accountId
	 * @return map
	 */
	public static Map<String, Object> frequencyLimitByOE2(Map<String, Object> map, String num, String accountId) {
		String[] dates = QueryConOrderInfo.covTime("0").split("-");
		String start_time = dates[0];
		String end_time = dates[1];
		// 1.2 查询我的订单（订单中心）
		try {
			List<OsOrderVo> oeList = OrderCenterUtil.getBroList("1", num, "", start_time, end_time);
			List<OsOrderVo> oeList_shop = OrderCenterUtil.getBroList("2", num, "", start_time, end_time);
			if (oeList != null) {
				if (oeList_shop != null) {
					oeList.addAll(oeList_shop);
				}
				for (OsOrderVo vo : oeList) {
					if (vo != null) {
						List itemList = vo.getOrderItem();// 获取一级明细 列表
						String orderState = vo.getOrderState(); // 订单状态
						if (itemList != null && !itemList.isEmpty()) {
							OsOrderItemVo orderItemVo = (OsOrderItemVo) itemList.get(0); // 获取一级明细对象
							String account = orderItemVo.getAccount();
							if (orderItemVo != null) {
								List<OsOrderItemValueVo> orderItemValueList = orderItemVo.getOrderItemValue(); // 获取二级明细列表
								if (orderItemValueList != null && !orderItemValueList.isEmpty()) {
									OsOrderItemValueVo orderItemValue = orderItemValueList.get(0); // 获取二级明细对象
									if (orderItemValue != null) {
										String oe_type = orderItemValue.getBusiType();
										// 如果订单类型还是续包， 且订单状态为已完成，且同一个宽带账号，
										// 且存在下单时间在10分钟内的
										if (("1".equals(oe_type) || "2".equals(oe_type) || "5".equals(oe_type)
												|| "6".equals(oe_type)||"16".equals(oe_type)||"17".equals(oe_type)) && orderState.equals("99")) {// 小于10分钟，返回订单提交过于频繁
											if (accountId.equals(account)
													&& DateUtil.difTimeForMin(vo.getCreateTime()) < 10) {
												map.put("result", "1");
												map.put("msg", "您提交订单过于频繁，请稍后再试。");
												return map;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			map.put("result", "0");
			map.put("vail_msgd", e);
			e.printStackTrace();
		}
		return map;
	}

	/**
	 * sso登录时imei为空的时候获取特定imei
	 * @param t
	 * @return
	 */
	public static String getImei(String channelId) {
		String imei;
		if("2".equals(channelId)){
			imei="2222"+IMEI;
		}else {
			imei="1111"+IMEI;
		}
		return imei;
	}

	/**
	 * 0,1,5类型登录3s内累计次数是否大于3
	 * @param t
	 * @return
	 */
	public static boolean getLoginLimit(String num) {
		try{
			String limit=RedisHome.getString(RedisCacheEnum.LOGINLIMIT, num);//获取用户次数缓存
			String loginlimit = CacheUtil.getLoginLimit();//获取字典表中限制次数
			//若有一个为空，则走正常的登录流程，只有缓存次数大于等于限制次数时，返回登录失败
			if(loginlimit != null && limit != null && Integer.parseInt(limit) >= Integer.parseInt(loginlimit)){
				return false;
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		return true;
	}

	/**
	 * 设置0,1,5类型登录3s内累计次数是否大于3
	 * @param num
	 * @return
	 */
	public static void setLoginNumLimit(String num) {
		String limit=RedisHome.getString(RedisCacheEnum.LOGINLIMIT, num);//获取用户次数缓存
		try{
			if(limit == null || limit.equals("")){//若用户次数缓存为空，则新建一个缓存
				RedisHome.addString(RedisCacheEnum.LOGINLIMIT, num, "1",0);
			}else{//若用户次数缓存不为空，则次数缓存自增
				incrLoginLimit(num);
			}
		}catch(Exception e){
			e.printStackTrace();
		}
	}

	/**
	 * 0,1,5类型登录成功3s内累计次数自增1
	 * @param num
	 * @return >0 有效，<=0无效  ；如果返回0，有可能是异常情况导致； 如果返回-1，有可能原来没有缓存
	 */
	public static long incrLoginLimit(String num){
		long number=RedisHome.incr(RedisCacheEnum.LOGINLIMIT, num);
		return number;
	}

	/**
	 * 判断传入的channelId是否是小于4位的数字
	 * @param channelId
	 */
	public static boolean isInteger(String channelId) {
		if(channelId.length()>4){
			return false;
		}
		Pattern pattern = Pattern.compile("^[-\\+]?[\\d]*$");
		return pattern.matcher(channelId).matches();
	}

	/**
	 * 验证IP是否属于某个IP段
	 * @param ip
	 * @return true表示在ip段里，false表示不再ip段里
	 */
	public static boolean ipExistsInIps(String ip,String ips){
		boolean flag = false;//默认
		String[] strings = ips.split(",");//分隔符
		for(String string:strings){
			if(string.indexOf("-") >=0){//获取带有-的ip段
				boolean exists=ipExistsInRange(ip,string);//判断用户ip是否在ip段里
				if(exists){
					flag=true;//如果在ip段里，返回true
					break;
				}
			}
		}
		return flag;//true表示在ip段里，false表示不再ip段里
	}

	/**验证IP是否属于某个IP段
	 * ipSection    IP段（以'-'分隔）
	 * ip           所验证的IP号码
	 */

	public static boolean ipExistsInRange(String ip,String ipSection) {

		ipSection = ipSection.trim();
		if(ip.contains(":")){
			return LocationQuery.ifMatchIpV6(ip, ipSection);
		}
		ip = ip.trim();

		int idx = ipSection.indexOf('-');

		String beginIP = ipSection.substring(0, idx);

		String endIP = ipSection.substring(idx + 1);

		return getIp2long(beginIP)<=getIp2long(ip) &&getIp2long(ip)<=getIp2long(endIP);

	}

	public static long getIp2long(String ip) {

		ip = ip.trim();

		String[] ips = ip.split("\\.");

		long ip2long = 0L;

		for (int i = 0; i < 4; ++i) {

			ip2long = ip2long << 8 | Integer.parseInt(ips[i]);

		}

		return ip2long;

	}
	
    /**
     * 是否熔断，对于部分实时性要求不高的接口，可以设置熔断降低服务器压力
     * @param cla
     * @param request
     * @return
     */
	public static boolean ifBreak(Class cla, HttpServletRequest request) {
		if (cla != null) {
			if (cla.equals(FirstPageAdvert.class) || cla.equals(SpBottom.class)) {
				String updateModel = DictionaryUtil.typeAndDateCodeToName(
						FirstPageAdvert.typeCode, "UPDATE_MODEL");
				if ("3".equals(updateModel)) {
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 * 获取和联盟参数
	 * @param request
	 * @return
	 */
	public static String getWMInfo(HttpServletRequest request){
		//和联盟参数
        String wmid = getString(ServletUtil.getStrParamter(request, "wmid"));
        String zjwmid = getString(ServletUtil.getStrParamter(request, "zjwmid"));
        String adid = getString(ServletUtil.getStrParamter(request, "adid"));
        String cid = getString(ServletUtil.getStrParamter(request, "cid"));
        String shopid = getString(ServletUtil.getStrParamter(request, "shopid"));
        String citycode = getString(ServletUtil.getStrParamter(request, "citycode"));
        String childrenchannel = getString(ServletUtil.getStrParamter(request, "childrenchannel"));
        String goodstype = getString(ServletUtil.getStrParamter(request, "goodstype"));
        String membertype = getString(ServletUtil.getStrParamter(request, "membertype"));
        String wminfo = String.format("%s_%s_%s_%s_%s_%s_%s_%s_%s", wmid, zjwmid, adid, cid, shopid, citycode, childrenchannel, goodstype, membertype);
        if (wminfo.length() > 4000) {
            wminfo = wminfo.substring(0, 4000);
        }
        return wminfo;
	}

    /**
     * 异网登录校验
     * @return
     */
    public static boolean diffLoginCheck(String num,String diffSession,Map<String,Object> map){
        if (StringUtils.isBlank(num) || StringUtils.isBlank(diffSession)){
            return false;
        }
        StringBuffer reqestUrl = new StringBuffer();
        reqestUrl.append(diffLoginCheckUrl).append("OpDiffNetSessionCheck.do?num=").append(num).append("&diffsession=").append(diffSession);
        loggin.info("异网登录校验参数 :" + reqestUrl);
        Date start = new Date();
        Document doc = null;
        String result  = "";
        try {
            result = HttpUtil.doHttpPost(reqestUrl.toString(), "", "UTF-8");
            Date end = new Date();
            loggin.info("请求时间："+(end.getTime()-start.getTime())/1000);
            loggin.info("请求结果："+result);
            if (StringUtils.isBlank(result)){
                loggin.error("异网登录校验接口异常返回为空！！！！！！");
                return false;
            }
			Map<String,Object> maps = (Map)JSON.parse(result);
            Map<String,Object> acc = (Map) maps.get("acc");
            if (acc == null){
            	loggin.error("返回账户为空！！！！！！");
            	return false;
			}
            map.put("acc",acc);
			return true;
        }catch (Exception e){
            loggin.error("异网登录校验接请求异常！！！！！！",e);
            return false;
        }
    }

	/**
	 * 将11位手机号码中间4位隐藏
	 * @param num 11位手机号
	 * @param replaceMark 替换的符号
	 * @return
	 */
	public static String getVagueNum(String num,String replaceMark) {
		if (StringUtils.isBlank(num) || StringUtils.isBlank(replaceMark) || num.length() != 11) {
			return num;
		}
		char[] nums = num.toCharArray();
		String replaceNum = "";
		for (int i = 0; i < nums.length; i++) {
			if (i < 3 || i > 6) {
				replaceNum += nums[i];
			} else {
				replaceNum += replaceMark;
			}
		}
		return replaceNum;
	}

	/**
	 * 获得模糊化名字，保留第一个字
	 * @param name
	 * @param replaceMark
	 * @return
	 */
	public static String getVagueName(String name,String replaceMark) {
		if (StringUtils.isBlank(name) || StringUtils.isBlank(replaceMark)) {
			return name;
		}
		char[] nums = name.toCharArray();
		if (nums.length < 2) {
			return name;
		}
		String replaceName = "";
		for (int i = 0; i < nums.length; i++) {
			if (i ==0) {
				replaceName += nums[i];
			} else {
				replaceName += replaceMark;
			}
		}
		return replaceName;
	}

	public static void main(String[] args) {
    	Map<String,Object> map = new HashMap();
		diffLoginCheck("18668711719","93VZ6HUP4SDV2LR55PR5NG9C",map);
		Map<String,Object> account = (Map) map.get("acc");
		Account acc = new Account(account);
		System.out.println(acc.toString());

	}

}