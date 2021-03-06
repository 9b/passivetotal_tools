% Generated by roxygen2 (4.1.1): do not edit by hand
% Please edit documentation in R/passive.R
\name{get_unique}
\alias{get_unique}
\title{Get unique resolution information including frequency count}
\usage{
get_unique(domain_or_ip)
}
\arguments{
\item{domain_or_ip}{atomic character vector containing an IP address or
domain name}
}
\value{
tbl_df
}
\description{
Each domain or IP address with results has a unique set of resolving items.
This call provides those unique items and a frequency count of how often
they show up in sorted order.
}
\note{
PassiveTotal API key must be set in the environment.
      See: \code{\link{passive_api_key}} for more details.
}
\examples{
\dontrun{
get_unique("passivetotal.org")
Source: local data frame [3 x 2]

               ip n
1  107.170.89.121 2
2 104.131.121.205 1
3 162.243.102.221 1
}
}
\seealso{
\href{PassiveTotal API documentation}{https://www.passivetotal.org/api/docs}
}

