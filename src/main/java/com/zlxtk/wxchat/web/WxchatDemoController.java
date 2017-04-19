package com.zlxtk.wxchat.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ConnectException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Date;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;

import com.zlxtk.wxchat.service.impl.MyX509TrustManager;
import com.zlxtk.wxchat.utils.Tools;
import com.zlxtk.wxchat.weixin.aes.WXBizMsgCrypt;

import net.sf.json.JSONObject;

@Controller
@RequestMapping("/web")
public class WxchatDemoController {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	public static String host = "http://mht.xiekuapp.com";
	public static String redirect_uri = "http://mht.xiekuapp.com/web/callBack";

	// 第三方平台access_token
	public static String component_token = "jmaihuotong";
	// 加密密匙
	public static String EncodingAESKey = "qazwsx1254cde36rfv789bgtyhn14mju8527ijkmloj";

	// 第三方平台appid
	public static String component_appid = "wx37e48ce9109897e9";
	// 第三方平台appsecret
	public static String component_appsecret = "d454c58f82d08e7ac7ae383fc49518b4";

	// 微信每隔10分钟推送的ticket
	public static String component_verify_ticket = "";

	// 第三方平台access_token
	public static String component_access_token = "";
	public static Long component_access_token_date=0L;

	// 第三方平台对公众号的授权码
	public static String authorization_code = "";
	
	//公众号appid
	public static String authorizer_appid = "wx3af5de11530976ee";
	

	// 第三方平台对公众号授权令牌
	public static String authorizer_access_token = "";
	public static Long authorizer_access_token_date=0L;
	// 授权令牌刷新令牌
	public static String authorizer_refresh_token = "";

	public static String xmlFormat = "<xml><ToUserName><![CDATA[toUser]]></ToUserName><Encrypt><![CDATA[%1$s]]></Encrypt></xml>";

	
	//登录用户的openid
	public static String openid = "";
	//登录用户的授权令牌
	public static String user_access_token = "";
	
	
	/**
	 * 接受component_verify_ticket 每10分钟回信会推送信息
	 */
	@RequestMapping("/acceptTicket")
	public void acceptTicket(HttpServletRequest request, HttpServletResponse response) throws Exception {

		logger.error("----------------------收到微信推送信息 begin:");

		String nonce = request.getParameter("nonce");
		logger.error("-----------------------nonce：" + nonce);
		String timestamp = request.getParameter("timestamp");
		logger.error("-----------------------timestamp：" + timestamp);
		String signature = request.getParameter("signature");
		logger.error("-----------------------signature：" + signature);
		String encrypt_type = request.getParameter("encrypt_type");
		logger.error("-----------------------encrypt_type：" + encrypt_type);
		String msgSignature = request.getParameter("msg_signature");
		logger.error("-----------------------msg_signature：" + msgSignature);

		// 1,保存component_verify_ticket
		StringBuilder sb = new StringBuilder();
		BufferedReader in = request.getReader();
		String line;
		while ((line = in.readLine()) != null) {
			sb.append(line);
		}
		String xml = sb.toString();
		logger.error("---------------接受到的原始数据：" + xml);
		if (encrypt_type.equals("aes")) {
			Document doc = DocumentHelper.parseText(xml);
			Element root = doc.getRootElement();
			String encrypt = root.elementText("Encrypt");
			String fromXML = String.format(xmlFormat, encrypt);
			WXBizMsgCrypt pc = new WXBizMsgCrypt(component_token, EncodingAESKey, component_appid);
			xml = pc.decryptMsg(msgSignature, timestamp, nonce, fromXML);
			logger.error("-----------------------解密后的原始数据：" + xml);
		}
		// json解析
		Document doc = DocumentHelper.parseText(xml);
		Element rootElt = doc.getRootElement();
		String InfoType=rootElt.elementText("InfoType");
		logger.error("-----------------------InfoType :" + InfoType);
		//微信推送数据类型
		if(InfoType.equals("component_verify_ticket")){
			logger.error("--------------------公众股每隔10分钟的消息推送 ----");
			
			component_verify_ticket = rootElt.elementText("ComponentVerifyTicket");
			logger.error("-----------------------component_verify_ticket :" + component_verify_ticket);
			
			// 2,如果component_access_token为空或快过期则请求component_access_token
			if (StringUtils.isEmpty(component_access_token)
					|| (new Date().getTime() - component_access_token_date >= 6000 * 1000)) {
				getComponentAccessToken();
			}
		}else if(InfoType.equals("authorized")){
			//公众股授权开发平台的推送
			logger.error("--------------------公众号授权开发平台推送 ----");
			String AuthorizerAppid = rootElt.elementText("AuthorizerAppid");
			logger.error("-----------------------授权的公众号appid---AuthorizerAppid :" + AuthorizerAppid);
			String AuthorizationCode=rootElt.elementText("AuthorizationCode");
			logger.error("-----------------------授权码---AuthorizationCode :" + AuthorizationCode);
		}else if(InfoType.equals("unauthorized")){
			//公众股取消授权开发平台的推送
			logger.error("--------------------公众号取消授权开发平台推送 ----");
			String AuthorizerAppid = rootElt.elementText("AuthorizerAppid");
			logger.error("-----------------------授权的公众号appid---AuthorizerAppid :" + AuthorizerAppid);
			String AuthorizationCode=rootElt.elementText("AuthorizationCode");
			logger.error("-----------------------授权码---AuthorizationCode :" + AuthorizationCode);
		}


		// 3,回复success
		output(response, "success");
		logger.error("---------------接受微信推送信息end：");
	}

	/**
	 * 根据微信推送的component_verify_ticket获取component_access_token
	 */
	public void getComponentAccessToken() throws Exception {
		String tokenUrl = "https://api.weixin.qq.com/cgi-bin/component/api_component_token";
		JSONObject json = new JSONObject();
		json.put("component_appid", component_appid);
		json.put("component_appsecret", component_appsecret);
		json.put("component_verify_ticket", component_verify_ticket);
		logger.error("-----------------------请求component_access_token的数据 :" + json.toString());

		JSONObject re = httpRequest(tokenUrl, "POST", json.toString());
		component_access_token = re.getString("component_access_token");
		logger.error("-----------------------component_access_token :" + component_access_token);
		String date = re.getString("expires_in");
		component_access_token_date = new Date().getTime();
		logger.error("-----------------------component_access_token_date :" + component_access_token_date);
	}

	/**
	 * 用户授权处理
	 * 
	 * @param request
	 * @param response
	 * @throws Exception
	 */
	@RequestMapping(value = "/goAuthor")
	public void goAuthor(HttpServletRequest request, HttpServletResponse response) throws Exception {
		
		logger.error("---------------用户访问授权页 begin:");
		
		// 后去预授权码pre_auth_code
		String codeUrl = "https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token="
				+ component_access_token;
		JSONObject json = new JSONObject();
		json.put("component_appid", component_appid);
		JSONObject re = httpRequest(codeUrl, "POST", json.toString());
		String pre_auth_code = re.get("pre_auth_code").toString();
		logger.error("-----------------------pre_auth_code :" + pre_auth_code);
		
		// 生成授权路径
		String url = "https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=" + component_appid
				+ "&pre_auth_code=" + pre_auth_code + "&redirect_uri=" + URLEncoder.encode(redirect_uri, "UTF-8");
		logger.error("-----------------------生成的授权路径 :" + url);
		// 重定向到授权路径
		response.sendRedirect(url);
		
		logger.error("---------------用户访问授权页 end!");
	}

	/**
	 * 授权后的回调处理,获取授权码，然后根据授权码获取公众号的授权信息，包括公众号的appid/
	 * authorizer_access_token/authorizer_refresh_token/授权的权限域
	 * 
	 * @param request
	 * @param response
	 * @throws Exception
	 */
	@RequestMapping(value = "/callBack")
	public void callBack(HttpServletRequest request, HttpServletResponse response) throws Exception {
		
		logger.error("---------------用户授权回调begin:");
		
		// 获取授权码authorization_code和授权码的过期时间
		authorization_code = request.getParameter("auth_code");
		logger.error("----------------------获取授权码authorization_code:"+authorization_code);

		// 获取令牌authorizer_access_token和authorizer_refresh_token和公众号的授权信息，并保存
		String codeUrl = "https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token="
				+ component_access_token;
		JSONObject json = new JSONObject();
		json.put("component_appid", component_appid);
		json.put("authorization_code", authorization_code);
		JSONObject re = httpRequest(codeUrl, "POST", json.toString());
		JSONObject info= re.getJSONObject("authorization_info");
		authorizer_appid=info.getString("authorizer_appid");
		logger.error("----------------------authorizer_appid:"+authorizer_appid);
		authorizer_access_token=info.getString("authorizer_access_token");
		logger.error("----------------------authorizer_access_token:"+authorizer_access_token);
		authorizer_access_token_date=new Date().getTime();
		logger.error("----------------------authorizer_access_token_date:"+authorizer_access_token_date);
		authorizer_refresh_token=info.getString("authorizer_refresh_token");
		logger.error("----------------------authorizer_refresh_token:"+authorizer_refresh_token);
		String func_info=info.getJSONArray("func_info").join(";");
		logger.error("----------------------func_info:"+func_info);
		
		
		
		logger.error("---------------用户授权回调end!");
	}
	
	/**
	 * 用户网页授权登录跳转页面
	 */
	@RequestMapping(value = "/login")
	public void login(HttpServletRequest request, HttpServletResponse response) throws Exception {
		String callback_uri="http://mht.xiekuapp.com/web/login/callback";
//		String url="https://open.weixin.qq.com/connect/qrconnect?appid="+authorizer_appid
//				+ "&redirect_uri="+URLEncoder.encode(callback_uri, "UTF-8")
//				+ "&response_type=code&scope=snsapi_login"
//				+ "&state=12345#wechat_redirect";
		String url="https://open.weixin.qq.com/connect/oauth2/authorize?appid="+authorizer_appid
				+ "&redirect_uri="+URLEncoder.encode(callback_uri, "UTF-8")
				+ "&response_type=code"
				+ "&scope=snsapi_userinfo"
//				+ "&scope=snsapi_base"
				+ "&state=123123123"
				+ "&component_appid="+component_appid
				+ "#wechat_redirect";
		logger.error("---------------用户登录网页授权路径--静默授权："+url);
		response.sendRedirect(url);
	}
	
	/**
	 * 用户网页授权登录
	 */
	@RequestMapping(value = "/login/callback")
	public void loginCallback(HttpServletRequest request, HttpServletResponse response) throws Exception {
		logger.error("---------------用户登录网页授权回调begin:");
		//获取code
		String code=request.getParameter("code");
		logger.error("-----------------------用户登录网页授权回调code:"+code);
		if(code==null){
			String callback_uri="http://mht.xiekuapp.com/web/login/callback";
			String url="https://open.weixin.qq.com/connect/oauth2/authorize?appid="+authorizer_appid
					+ "&redirect_uri="+URLEncoder.encode(callback_uri, "UTF-8")
					+ "&response_type=code"
					+ "&scope=snsapi_userinfo"
//					+ "&scope=snsapi_base"
					+ "&state=123123123"
					+ "&component_appid="+component_appid
					+ "#wechat_redirect";
			logger.error("---------------用户登录网页授权路径："+url);
			response.sendRedirect(url);
			return;
		}
		//获取access_token，openid
//		String tokenUrl="https://api.weixin.qq.com/sns/oauth2/access_token?appid="+authorizer_appid
//				+ "&secret="+component_appsecret
//				+ "&code="+code
//				+ "&grant_type=authorization_code";
		String tokenUrl="https://api.weixin.qq.com/sns/oauth2/component/access_token?appid="+authorizer_appid
				+ "&code="+code
				+ "&grant_type=authorization_code"
				+ "&component_appid="+component_appid
				+ "&component_access_token="+component_access_token;
		JSONObject re = httpRequest(tokenUrl, "GET", null);
		logger.error("------------------------用户网页授权获取的token："+re.toString());
		user_access_token=re.getString("access_token");
		String refresh_token=re.getString("refresh_token");
		openid=re.getString("openid");
		
		logger.error("---------------用户登录网页授权回调end:");
	}
	
	/**
	 * 调用公众号获取用户信息接口
	 */
	@RequestMapping(value = "/findUserInfo")
	public void findUserInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
		logger.error("---------------调用公众号获取用户信息接口begin:");
		String userUrl="https://api.weixin.qq.com/cgi-bin/user/info?access_token="+authorizer_access_token
				+ "&openid="+openid
				+ "&lang=zh_CN";
		JSONObject user = httpRequest(userUrl, "GET", null);
		logger.error("-------------------------用户信息："+user.toString());
		
		
		logger.error("---------------调用公众号获取用户信息接口end:");
	}
	/**
	 * 调用网页授权获取用户信息接口
	 */
	@RequestMapping(value = "/findUserInfoForWeb")
	public void findUserInfoForWeb(HttpServletRequest request, HttpServletResponse response) throws Exception {
		logger.error("---------------调用网页授权获取用户信息接口begin:");
		//网页授权获取用户信息
		String userUrl="https://api.weixin.qq.com/sns/userinfo?access_token="+user_access_token
				+ "&openid="+openid;
		JSONObject user = httpRequest(userUrl, "GET", null);
		logger.error("-------------------------网页授权获取的用户基本信息："+user.toString());
		
		logger.error("---------------调用网页授权获取用户信息接口end:");
	}
	
	

	/**
	 * 对访问回复信息
	 * 
	 * @param response
	 * @param returnvaleue
	 *            要回复的字符串
	 */
	public void output(HttpServletResponse response, String returnvaleue) {
		try {
			PrintWriter pw = response.getWriter();
			pw.write(returnvaleue);
			pw.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 访问URL,获取JSON
	 * 
	 * @param requestUrl
	 * @param requestMethod
	 * @param outputStr
	 * @return
	 */
	public static JSONObject httpRequest(String requestUrl, String requestMethod, String outputStr) {
		JSONObject jsonObject = null;
		StringBuffer buffer = new StringBuffer();
		try {
			// 创建SSLContext对象，并使用我们指定的信任管理器初始化
			TrustManager[] tm = { new MyX509TrustManager() };
			SSLContext sslContext = SSLContext.getInstance("SSL", "SunJSSE");
			sslContext.init(null, tm, new java.security.SecureRandom());
			// 从上述SSLContext对象中得到SSLSocketFactory对象
			SSLSocketFactory ssf = sslContext.getSocketFactory();

			URL url = new URL(requestUrl);
			HttpsURLConnection httpUrlConn = (HttpsURLConnection) url.openConnection();
			httpUrlConn.setSSLSocketFactory(ssf);

			httpUrlConn.setDoOutput(true);
			httpUrlConn.setDoInput(true);
			httpUrlConn.setUseCaches(false);
			// 设置请求方式（GET/POST）
			httpUrlConn.setRequestMethod(requestMethod);

			if ("GET".equalsIgnoreCase(requestMethod))
				httpUrlConn.connect();

			// 当有数据需要提交时
			if (null != outputStr) {
				OutputStream outputStream = httpUrlConn.getOutputStream();
				// 注意编码格式，防止中文乱码
				outputStream.write(outputStr.getBytes("UTF-8"));
				outputStream.close();
			}

			// 将返回的输入流转换成字符串
			InputStream inputStream = httpUrlConn.getInputStream();
			InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "utf-8");
			BufferedReader bufferedReader = new BufferedReader(inputStreamReader);

			String str = null;
			while ((str = bufferedReader.readLine()) != null) {
				buffer.append(str);
			}
			bufferedReader.close();
			inputStreamReader.close();
			// 释放资源
			inputStream.close();
			inputStream = null;
			httpUrlConn.disconnect();
			jsonObject = JSONObject.fromObject(buffer.toString());
		} catch (ConnectException ce) {
			ce.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return jsonObject;
	}

	/**
	 * 验证是否是从微信服务器返回调用
	 * 
	 * @param signature
	 * @param timestamp
	 * @param nonce
	 * @param echostr
	 * @param token
	 */
	private boolean validate(String signature, String timestamp, String nonce, String echostr, String token) {
		if (!StringUtils.isEmpty(timestamp) && !StringUtils.isEmpty(nonce) && !StringUtils.isEmpty(echostr)
				&& !StringUtils.isEmpty(signature)) {
			// 验证
			return Tools.checkSignature(token, signature, timestamp, nonce);
		}
		return false;
	}

}
