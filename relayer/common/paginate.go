package common

import "fmt"

type Paginate struct {
	startSeq uint64
	endSeq   uint64
	limit    uint64
	page     uint64
}

func NewPaginate(startSeq, endSeq, limit uint64) *Paginate {
	return &Paginate{
		startSeq: startSeq,
		endSeq:   endSeq,
		limit:    limit,
		page:     0,
	}
}

func (p *Paginate) HasNext() bool {
	return p.startSeq <= p.endSeq
}

func (p *Paginate) Next() (uint64, uint64, error) {
	if !p.HasNext() {
		return 0, 0, fmt.Errorf("no more pages available")
	}

	start := p.startSeq
	end := p.startSeq + p.limit - 1

	if end > p.endSeq {
		end = p.endSeq
	}

	p.startSeq = end + 1
	p.page++

	return start, end, nil
}
