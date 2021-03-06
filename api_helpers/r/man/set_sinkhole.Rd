% Generated by roxygen2 (4.1.1): do not edit by hand
% Please edit documentation in R/passive.R
\name{set_sinkhole}
\alias{set_sinkhole}
\title{Set sinkhole status of IP address}
\usage{
set_sinkhole(domain_or_ip, is_sinkhole)
}
\arguments{
\item{domain_or_ip}{atomic character vector containing an IP address or
domain name}

\item{is_sinkhole}{logical (\code{TRUE} if sinkhole)}
}
\description{
PassiveTotal allows users to notate if an IP address is a known sinkhole.
These values are shared globally with everyone in the platform.
}
\note{
PassiveTotal API key must be set in the environment.
      See: \code{\link{passive_api_key}} for more details.
}
\seealso{
\href{PassiveTotal API documentation}{https://www.passivetotal.org/api/docs}
}

