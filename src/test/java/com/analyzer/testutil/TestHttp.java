package com.analyzer.testutil;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.traffic.HttpTrafficLog;

import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test fixtures that build Mockito-mocked Montoya objects. The Montoya static factories
 * (e.g. {@code HttpHeader.httpHeader(...)}, {@code HttpRequest.httpRequestFromUrl(...)}) only work
 * inside a running Burp because their implementations are supplied by Burp at load time, so unit
 * tests must mock the interfaces directly rather than construct real instances.
 *
 * <p>Stubs are {@code lenient()} so a test that exercises only part of a request/response doesn't
 * trip Mockito's strict unnecessary-stubbing check.</p>
 */
public final class TestHttp {
    private TestHttp() {}

    public static HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        lenient().when(h.name()).thenReturn(name);
        lenient().when(h.value()).thenReturn(value);
        return h;
    }

    public static HttpResponse response(int status, String reason, List<HttpHeader> headers, String body) {
        HttpResponse r = mock(HttpResponse.class);
        lenient().when(r.statusCode()).thenReturn((short) status);
        lenient().when(r.reasonPhrase()).thenReturn(reason);
        lenient().when(r.headers()).thenReturn(headers);
        lenient().when(r.bodyToString()).thenReturn(body);
        return r;
    }

    public static HttpRequest request(String method, String url, String path,
                                      List<HttpHeader> headers, String body,
                                      List<ParsedHttpParameter> params) {
        HttpRequest q = mock(HttpRequest.class);
        lenient().when(q.method()).thenReturn(method);
        lenient().when(q.url()).thenReturn(url);
        lenient().when(q.path()).thenReturn(path);
        lenient().when(q.headers()).thenReturn(headers);
        lenient().when(q.bodyToString()).thenReturn(body);
        lenient().when(q.parameters()).thenReturn(params);
        return q;
    }

    /** Convenience: a simple GET with the given headers and no body/params. */
    public static HttpRequest get(String url, HttpHeader... headers) {
        return request("GET", url, pathOf(url), Arrays.asList(headers), "", List.of());
    }

    public static ParsedHttpParameter param(HttpParameterType type, String name, String value) {
        ParsedHttpParameter p = mock(ParsedHttpParameter.class);
        lenient().when(p.type()).thenReturn(type);
        lenient().when(p.name()).thenReturn(name);
        lenient().when(p.value()).thenReturn(value);
        return p;
    }

    /** An AnalysisContext wired to a deep-stubbed MontoyaApi (so api().logging()... never NPEs). */
    public static AnalysisContext ctx(HttpRequest req, HttpResponse resp) {
        MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
        return new AnalysisContext(api, req, resp, "test", new HttpTrafficLog());
    }

    private static String pathOf(String url) {
        int scheme = url.indexOf("://");
        int slash = scheme < 0 ? url.indexOf('/') : url.indexOf('/', scheme + 3);
        return slash < 0 ? "/" : url.substring(slash);
    }
}
