package com.zlxtk.wxchat;

import java.net.URLEncoder;

import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.w3c.dom.NodeList;

import com.zlxtk.wxchat.web.WxchatDemoController;
import com.zlxtk.wxchat.weixin.aes.AesException;
import com.zlxtk.wxchat.weixin.aes.WXBizMsgCrypt;

@RunWith(SpringRunner.class)
@SpringBootTest
public class WxchatApplicationTests {

	@Test
	public void contextLoads() {
		String xml = "<xml>    <AppId><![CDATA[wx37e48ce9109897e9]]></AppId>    <Encrypt><![CDATA[Wi7sOTFEa1p/eB2IEK/RDz1l5Uq02zibSeLDXsWotkq/Kz3ximHPgOwqz923of3eJPafRQ3dBHHOBUgRNUliC1XyJ+vGhstwr1uSuwIIKVObjZHjhwDC+Vs1tkOP0V47GqtoM3I7R7gGhSsVHkl8qGIX8CPFn2Ozblckwrvop9dXkapQJAvrAcA2DdZKCiuxC8Gfbunwkay3OjWQKpZ0RODv+EG0py56XMWa/MfAwbxIt8JtRhxoNSt4X5JN8c8t5ZIwZCWF5Owrd3Bu3HtC+ZEZG3GqTxfR4+Ze7bNE9T/D2TUJEqrzcz1Sq2GtPhdjlqY2NJsjPQ736yO7JMPW8cb6q77AXSEL9saKsh7O/3HyKcHCjuNibxwPxQIV1OajQgHdXx1hjIeTWsrFVqNJGBBTQ8OsTwWGDizgX1D3MGtpDX+DNpjzFGHNcN/xCtK1p4sIv2hw6VMU/RFzmutNPQ==]]></Encrypt></xml>";
		try {

			Document doc = DocumentHelper.parseText(xml);
			Element root = doc.getRootElement();
			String encrypt = root.elementText("Encrypt");
			String fromXML = String.format(WxchatDemoController.xmlFormat, encrypt);
			System.out.println(fromXML);

			WXBizMsgCrypt pc = new WXBizMsgCrypt(WxchatDemoController.component_token,
					"qazwsx1254cde36rfv789bgtyhn14mju8527ijkmloj", WxchatDemoController.component_appid);
			xml = pc.decryptMsg("388a61cebc51af0b9c01f4b8149bba601d266e82", "1490355911", "588124594", fromXML);
			System.out.println(xml);
			
			System.out.println(URLEncoder.encode("http://mht.xiekuapp.com/wxchatdemo/web/callBack","utf-8"));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
