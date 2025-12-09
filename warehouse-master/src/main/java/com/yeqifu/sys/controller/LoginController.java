package com.yeqifu.sys.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.LineCaptcha;
import cn.hutool.core.util.IdUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.yeqifu.sys.common.ActiverUser;
import com.yeqifu.sys.common.Constast;
import com.yeqifu.sys.common.ResultObj;
import com.yeqifu.sys.common.WebUtils;
import com.yeqifu.sys.entity.Loginfo;
import com.yeqifu.sys.entity.User;
import com.yeqifu.sys.service.ILoginfoService;
import com.yeqifu.sys.service.IUserService;
import com.yeqifu.sys.vo.UserVo;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Date;

/**
 * 登陆前端控制器
 * @Author: 落亦-
 * @Date: 2019/11/21 21:33
 */
@RestController
@RequestMapping("login")
public class LoginController {

    @Autowired
    private ILoginfoService loginfoService;

    @Autowired
    private IUserService userService;

    @RequestMapping("login")
    public ResultObj login(UserVo userVo,String code,HttpSession session){

        //获得存储在session中的验证码
        String sessionCode = (String) session.getAttribute("code");
        if (code!=null&&sessionCode.equals(code)){
            Subject subject = SecurityUtils.getSubject();
            AuthenticationToken token = new UsernamePasswordToken(userVo.getLoginname(),userVo.getPwd());
            try {
                //对用户进行认证登陆
                subject.login(token);
                //通过subject获取以认证活动的user
                ActiverUser activerUser = (ActiverUser) subject.getPrincipal();
                //将user存储到session中
                WebUtils.getSession().setAttribute("user",activerUser.getUser());
                //记录登陆日志
                Loginfo entity = new Loginfo();
                entity.setLoginname(activerUser.getUser().getName()+"-"+activerUser.getUser().getLoginname());
                entity.setLoginip(WebUtils.getRequest().getRemoteAddr());
                entity.setLogintime(new Date());
                loginfoService.save(entity);

                return ResultObj.LOGIN_SUCCESS;
            } catch (AuthenticationException e) {
                e.printStackTrace();
                return ResultObj.LOGIN_ERROR_PASS;
            }
        }else {
            return ResultObj.LOGIN_ERROR_CODE;
        }

    }

    /**
     * 得到登陆验证码
     * @param response
     * @param session
     * @throws IOException
     */
    @RequestMapping("getCode")
    public void getCode(HttpServletResponse response, HttpSession session) throws IOException{
        //定义图形验证码的长和宽
        LineCaptcha lineCaptcha = CaptchaUtil.createLineCaptcha(116, 36,4,5);
        session.setAttribute("code",lineCaptcha.getCode());
        try {
            ServletOutputStream outputStream = response.getOutputStream();
            lineCaptcha.write(outputStream);
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 用户注册
     * 保持现有登录功能不变的前提下，新增一个独立的注册入口
     * @param userVo
     * @return
     */
    @RequestMapping("register")
    public ResultObj register(UserVo userVo){
        try {
            // 简单参数校验
            if (userVo.getLoginname() == null || userVo.getLoginname().trim().isEmpty()
                    || userVo.getPwd() == null || userVo.getPwd().trim().isEmpty()) {
                return new ResultObj(Constast.ERROR,"用户名和密码不能为空");
            }

            // 校验登录名是否已存在
            QueryWrapper<User> queryWrapper = new QueryWrapper<>();
            queryWrapper.eq("loginname",userVo.getLoginname());
            User existUser = userService.getOne(queryWrapper);
            if (existUser != null){
                return new ResultObj(Constast.ERROR,"该登录名已被占用");
            }

            // 生成盐并对密码加密，保持与现有登陆加密规则一致
            String salt = IdUtil.simpleUUID().toUpperCase();
            userVo.setSalt(salt);
            String pwd = new Md5Hash(userVo.getPwd(),salt,Constast.HASHITERATIONS).toString();
            userVo.setPwd(pwd);

            // 设置默认属性：普通可用用户、默认头像
            userVo.setType(Constast.USER_TYPE_NORMAL);
            userVo.setAvailable((Integer) Constast.AVAILABLE_TRUE);
            userVo.setImgpath(Constast.DEFAULT_IMG_USER);

            userService.save(userVo);
            return new ResultObj(Constast.OK,"注册成功");
        } catch (Exception e) {
            e.printStackTrace();
            return new ResultObj(Constast.ERROR,"注册失败");
        }
    }

}
