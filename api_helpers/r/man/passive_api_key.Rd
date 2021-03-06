% Generated by roxygen2 (4.1.1): do not edit by hand
% Please edit documentation in R/passive.R
\name{passive_api_key}
\alias{passive_api_key}
\title{Get or set PASSIVETOTAL_API_KEY value}
\usage{
passive_api_key(force = FALSE)
}
\arguments{
\item{force}{Force setting a new PassiveTotal API key for the current environment?}
}
\value{
atomic character vector containing the PassiveTotal API key
}
\description{
The API wrapper functions in this package all rely on a PassiveTotal API
key residing in the environment variable \code{PASSIVETOTAL_API_KEY}. The
easiest way to accomplish this is to set it in the `.Renviron` file in your
home directory.
}

