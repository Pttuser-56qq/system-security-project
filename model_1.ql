import cpp
import semmle.code.cpp.dataflow.DataFlow

class SslGetPeerCertificateCall extends FunctionCall {
  SslGetPeerCertificateCall() {
    this.getTarget().hasName("SSL_get0_peer_certificate") or
    this.getTarget().hasName("SSL_get1_peer_certificate") or
	this.getTarget().hasName("SSL_get_peer_certificate")
  }
}

class SslVerifyResultCall extends FunctionCall {
  SslVerifyResultCall() {
    this.getTarget().hasName("SSL_get_verify_result")
  }
}

class SslDataTransferCall extends FunctionCall {
  SslDataTransferCall() {
    this.getTarget().hasName("SSL_read") or
    this.getTarget().hasName("SSL_write")
  }
}

from SslGetPeerCertificateCall cert, SslDataTransferCall data
where cert.getEnclosingFunction() = data.getEnclosingFunction() and
not exists(SslVerifyResultCall verify |
    verify.getEnclosingFunction() = cert.getEnclosingFunction() and
    verify.getLocation().getStartLine() < data.getLocation().getStartLine()
)
select data, "Potential unsafe data transfer without certificate verification."
