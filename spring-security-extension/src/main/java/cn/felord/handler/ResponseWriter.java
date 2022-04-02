package cn.felord.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


public abstract class ResponseWriter {
    private static final Logger log = Logger.getLogger(ResponseWriter.class.getSimpleName());
    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    /**
     * Write.
     *
     * @param request  the request
     * @param response the response
     * @throws IOException the io exception
     */
    public void write(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (response.isCommitted()) {
            log.log(Level.INFO,"Response has already been committed");
            return;
        }
        response.setStatus(HttpServletResponse.SC_OK);
        response.setCharacterEncoding("utf-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        String resBody = objectMapper.writeValueAsString(this.body(request));
        PrintWriter printWriter = response.getWriter();
        printWriter.print(resBody);
        printWriter.flush();
        printWriter.close();
    }

    /**
     * Msg string.
     *
     * @param request the request
     * @return the string
     */
    protected abstract Map<String,Object> body(HttpServletRequest request);

}
