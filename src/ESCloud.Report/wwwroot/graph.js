document.addEventListener("DOMContentLoaded", function () {
  var dataNode = document.getElementById("escloud-graph");
  var host = document.getElementById("attack-graph");
  if (!dataNode || !host) {
    return;
  }

  if (typeof vis === "undefined" || !vis.Network) {
    host.textContent = "The attack-path graph library did not load.";
    return;
  }

  var payload = JSON.parse(dataNode.textContent || "{}");
  var nodes = new vis.DataSet(payload.nodes || []);
  var edges = new vis.DataSet((payload.edges || []).map(function (edge) {
    return {
      from: edge.from,
      to: edge.to,
      width: edge.highlight ? 3 : 1,
      color: edge.highlight ? "#5eefc5" : "#355066",
      arrows: "to"
    };
  }));

  var network = new vis.Network(host, { nodes: nodes, edges: edges }, {
    autoResize: true,
    layout: {
      hierarchical: {
        enabled: true,
        direction: "LR",
        sortMethod: "directed",
        levelSeparation: 200,
        nodeSpacing: 120,
        shakeTowards: "roots"
      }
    },
    physics: false,
    nodes: {
      shape: "box",
      margin: 12,
      widthConstraint: { maximum: 280 },
      font: { face: "Avenir Next, Segoe UI, sans-serif", size: 20, color: "#f4f7fb" },
      borderWidth: 0,
      color: { background: "#163044", highlight: { background: "#1d3d54", border: "#5eefc5" } }
    },
    groups: {
      forged: { color: { background: "#ff5d6c" }, font: { color: "#1a0a0c", size: 20 } },
      ca: { color: { background: "#ffc14d" }, font: { color: "#1c1406", size: 20 } },
      "public-ca": { color: { background: "#c9a15b" }, font: { color: "#1c1406", size: 20 } },
      binding: { color: { background: "#0f6e56" }, font: { color: "#e7fff6", size: 20 } },
      ga: { color: { background: "#ff5d6c" }, font: { color: "#1a0a0c", size: 20 } },
      admin: { color: { background: "#24506e" }, font: { color: "#f4f7fb", size: 20 } },
      profile: { color: { background: "#1d4e89" }, font: { color: "#f4f7fb", size: 20 } }
    },
    edges: { smooth: false },
    interaction: { hover: true }
  });
  var fit = function () { network.fit({ animation: false }); };
  requestAnimationFrame(fit);
  setTimeout(fit, 60);
});
