const Party = require("../models/Party");

const partyController = {
    create: async (req, res) => {
        try {
            const party = {
                title: req.body.title,
                author: req.body.author,
                description: req.body.description,
                budget: req.body.budget,
            }
            const response = await Party.create(party);

            res.status(201).json({ response, msg: "Festa criada com sucesso." });
        } catch (error) {
            console.log(`Erro: ${error}`);
        }
    },
    getAll: async (req, res) => {
        try {
            const parties = await Party.find();
            
            res.json(parties);
        } catch (error) {
            console.log(`Erro: ${error}`);
        }
    },
    get: async (req, res) => {
        try {
            const id = req.params.id;
            const party = await Party.findById(id);

            if (!party) {
                res.status(404).json({ msg: "Festa não encontrada." });
                return;
            }

            res.json(party);
        } catch (error) {
            console.log(`Erro: ${error}`);
        }
    },
    delete: async (req, res) => {
        try {
            const id = req.params.id;
            const party = await Party.findById(id);

            if (!party) {
                res.status(404).json({ msg: "Festa não encontrada." });
                return;
            }

            const deletedParty = await Party.findByIdAndDelete(id);

            res.status(200).json({ deletedParty, mag: "Festa deletada com sucesso." });
        } catch (error) {
            console.log(`Erro: ${error}`);
        }
    },
    update: async (req, res) => {
        try {
            const id = req.params.id;
            const party = {
                title: req.body.title,
                author: req.body.author,
                description: req.body.description,
                budget: req.body.budget,
            }

            const updatedParty = await Party.findByIdAndUpdate(id, party);

            if (!updatedParty) {
                res.status(404).json({ msg: "Festa não encontrada." });
                return;
            }

            res.status(200).json({ party, msg: "Festa atualizada com sucesso." });
        } catch (error) {
            console.log(`Erro: ${error}`);
        }
    }
};

module.exports = partyController;
