package app

// hostUnderLoad is a variable so tests can inject the host-load measurement;
// production always points at the platform implementation.
var hostUnderLoad = measureHostLoad
