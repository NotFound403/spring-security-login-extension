package cn.felord.configuers.authentication;


import cn.felord.configuers.authentication.captcha.CaptchaLoginFilterConfigurer;
import cn.felord.configuers.authentication.miniapp.MiniAppLoginFilterConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.DefaultSecurityFilterChain;


public class LoginFilterSecurityConfigurer<H extends HttpSecurityBuilder<H>> extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, H> {
    private final CaptchaLoginFilterConfigurer<H> captchaLoginFilterConfigurer = new CaptchaLoginFilterConfigurer<>();
    private final MiniAppLoginFilterConfigurer<H> miniAppLoginFilterConfigurer = new MiniAppLoginFilterConfigurer<>();

    public LoginFilterSecurityConfigurer<H> captchaLogin(Customizer<CaptchaLoginFilterConfigurer<H>> captchaLoginFilterConfigurerCustomizer) {
        captchaLoginFilterConfigurerCustomizer.customize(captchaLoginFilterConfigurer);
        return this;
    }

    public LoginFilterSecurityConfigurer<H> miniAppLogin(Customizer<MiniAppLoginFilterConfigurer<H>> miniAppLoginFilterConfigurerCustomizer) {
        miniAppLoginFilterConfigurerCustomizer.customize(miniAppLoginFilterConfigurer);
        return this;
    }

    @Override
    public void init(H builder) throws Exception {
        this.captchaLoginFilterConfigurer.init(builder);
        this.miniAppLoginFilterConfigurer.init(builder);
    }

    @Override
    public void configure(H builder) throws Exception {
        this.captchaLoginFilterConfigurer.configure(builder);
        this.miniAppLoginFilterConfigurer.configure(builder);
    }
}
