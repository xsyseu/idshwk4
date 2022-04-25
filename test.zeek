event zeek_init()
{
    local r1=SumStats::Reducer($stream="http_response",$apply=set(SumStats::SUM));
    local r2=SumStats::Reducer($stream="http_response_404",$apply=set(SumStats::SUM));
    local r3=SumStats::Reducer($stream="http_response_404",$apply=set(SumStats::UNIQUE));
    SumStats::create([$name="detect_404_attacker",
                      $epoch=10min,
                      $reducers=set(r1,r2,r3),
                      $epoch_result(ts:time,key:SumStats::Key,result:SumStats::Result)=
                        {
                            local ratio_404:double=result["http_response_404"]$sum/result["http_response"]$sum;
                            local ratio_unique_404:double=result["http_response_404"]$unique/result["http_response_404"]$sum;
                            if(result["http_response"]$sum>2&&ratio_404>0.2&&ratio_unique_404>0.5)
                                print fmt("%s is a scanner with %.0f scan attemps on %d urls",key$host,result["http_response_404"]$sum,result["http_response_404"]$unique);
                        }]);
}
event http_reply(c:connection,version:string,code:count,reason:string)
{
    if(code==404)
    {
        SumStats::observe("http_response_404",
        SumStats::Key($host=c$id$orig_h),
        SumStats::Observation($str=c$http$uri));
    }
    SumStats::observe("http_response",
        SumStats::Key($host=c$id$orig_h),
        SumStats::Observation($str=c$http$uri));
}