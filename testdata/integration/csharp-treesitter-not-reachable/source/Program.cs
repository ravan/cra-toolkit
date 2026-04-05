using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace TestApp;

[ApiController]
[Route("[controller]")]
public class DataController : ControllerBase
{
    [HttpGet("serialize")]
    public IActionResult Serialize([FromQuery] string name)
    {
        var data = new { Name = name, Timestamp = DateTime.UtcNow };
        var json = JsonConvert.SerializeObject(data);
        return Content(json, "application/json");
    }
}
