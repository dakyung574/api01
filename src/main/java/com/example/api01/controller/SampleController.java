package com.example.api01.controller;

import io.swagger.annotations.ApiOperation;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/sample")
public class SampleController {

    @ApiOperation("Sample Get doA")
    @GetMapping("/doA")
    public List<String> doA() {
        return Arrays.asList("AAA","BBB","CCC");
    }

    @GetMapping("/getArr")
    public String[] getArr() {
        return new String[] {"AAA","BBB","CCC"};
    }
}
