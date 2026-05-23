package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func parseQueryParams(c *gin.Context) (*utils.QueryParams, bool) {
	params, err := utils.ParseQueryParams(c)
	if err != nil {
		utils.ProblemBadRequest(c, err.Error())
		return nil, false
	}
	return params, true
}

func parseListQuery(c *gin.Context) (*utils.QueryParams, *repository.ListQuery, bool) {
	params, ok := parseQueryParams(c)
	if !ok {
		return nil, nil, false
	}

	query, err := utils.QueryParamsToListQuery(params)
	if err != nil {
		utils.ProblemBadRequest(c, err.Error())
		return nil, nil, false
	}

	return params, query, true
}
