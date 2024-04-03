go build -buildmode=plugin -o plugin/targets/badasn/badasn.so plugin/targets/badasn/badasn.go 
go build -buildmode=plugin -o plugin/targets/censys/censys.so plugin/targets/censys/censys.go 
go build -buildmode=plugin -o plugin/targets/shodan/shodan.so plugin/targets/shodan/shodan.go 
go build -buildmode=plugin -o plugin/targets/ipsum/ipsum.so plugin/targets/ipsum/ipsum.go
go build -buildmode=plugin -o plugin/c2/Trochilus/trochilus_banner.so plugin/c2/Trochilus/trochilus_banner.go 
