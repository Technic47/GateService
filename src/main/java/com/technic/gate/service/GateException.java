package com.technic.gate.service;

/** Ошибка, текст которой можно показать пользователю как есть. */
public class GateException extends RuntimeException {

    public GateException(String message) {
        super(message);
    }
}
