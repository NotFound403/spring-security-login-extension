package cn.felord.configuers.authentication;


import cn.felord.configuers.authentication.captcha.CaptchaLoginFilterConfigurer;
import cn.felord.configuers.authentication.miniapp.MiniAppLoginFilterConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.DefaultSecurityFilterChain;


public class LoginFilterSecurityConfigurer<H extends HttpSecurityBuilder<H>> extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, H> {
    private CaptchaLoginFilterConfigurer<H> captchaLoginFilterConfigurer;
    private MiniAppLoginFilterConfigurer<H> miniAppLoginFilterConfigurer;

    public LoginFilterSecurityConfigurer<H> captchaLogin(Customizer<CaptchaLoginFilterConfigurer<H>> captchaLoginFilterConfigurerCustomizer) {
        captchaLoginFilterConfigurerCustomizer.customize(lazyInitCaptchaLoginFilterConfigurer());
        return this;
    }

    public LoginFilterSecurityConfigurer<H> miniAppLogin(Customizer<MiniAppLoginFilterConfigurer<H>> miniAppLoginFilterConfigurerCustomizer) {
        miniAppLoginFilterConfigurerCustomizer.customize(lazyInitMiniAppLoginFilterConfigurer());
        return this;
    }

    @Override
    public void init(H builder) throws Exception {
          if (captchaLoginFilterConfigurer!=null){
              captchaLoginFilterConfigurer.init(builder);
          }
          if (miniAppLoginFilterConfigurer!=null){
              miniAppLoginFilterConfigurer.init(builder);
          }
    }

    @Override
    public void configure(H builder) throws Exception {
       if (captchaLoginFilterConfigurer!=null){
           captchaLoginFilterConfigurer.configure(builder);
       }
       if (miniAppLoginFilterConfigurer!=null){
           miniAppLoginFilterConfigurer.configure(builder);
       }
    }

    private CaptchaLoginFilterConfigurer<H> lazyInitCaptchaLoginFilterConfigurer() {
        if (captchaLoginFilterConfigurer == null) {
            this.captchaLoginFilterConfigurer = new CaptchaLoginFilterConfigurer<>();
        }
        return captchaLoginFilterConfigurer;
    }

    private MiniAppLoginFilterConfigurer<H> lazyInitMiniAppLoginFilterConfigurer() {
        if (miniAppLoginFilterConfigurer == null) {
            this.miniAppLoginFilterConfigurer = new MiniAppLoginFilterConfigurer<>();
        }
        return miniAppLoginFilterConfigurer;
    }
}
