package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	e.GET("/hello", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"msg": "hello"})
	})

	e.POST("/double", func(c echo.Context) error {
		var body struct {
			Number float64 `json:"number"`
		}
		c.Bind(&body)
		return c.JSON(http.StatusOK, map[string]float64{"double": body.Number * 2})
	})

	e.Start(":8080")
}
